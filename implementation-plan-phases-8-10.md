# sipnab — Integration & Observability Plan (Phases 8–10)

**Project:** sipnab — SIP & RTP capture, analysis, and security tool
**Repository:** github.com/NormB/sipnab
**Domain:** sipnab.com
**License:** MIT OR Apache-2.0
**Author:** Norm Brandinger

**Slots into:** `implementation-plan-v6.md` as Phases 8–10 (follow Phase 7 — Polish, Packaging, Release).
**Origin:** Issue request — *"So that I can have a local AI agent go and talk to a server that we're debugging stuff on."* — expanded after architectural review to cover the full integration story (AI agents, scripts/SDKs, dashboards, observability).

## Phase Roadmap

| Phase | Theme | Release | Status |
|---|---|---|---|
| 8 | Foundational cleanups (parse-path consolidation, log→tracing) + MCP server mode (stdio + HTTP) + feature-gated event bus exposing MCP / WebSocket / SSE | v0.4.0 | Planned |
| 9 | REST API self-description (OpenAPI) and observability (OpenTelemetry) | v0.5.0 | Planned |
| 10 | NATS event bus | — | **Deferred to Future Considerations.** WebSocket and SSE from 8.4b cover the "external consumers" case for the vast majority of deployments. Design preserved; un-defer when an operator with NATS in production specifically asks. |
| 11 | Cross-stream statistical analysis and perceptual MOS (NISQA) | v0.6.0 | Planned (design before Phase 8 ships, build after) |
| 12 | Documentation & website overhaul | Threaded across v0.4.0–v0.6.0 | Planned (infrastructure + CI quality gates first, content progressive) |

## ★ Priority Sequencing

Items marked **★** below are the highest-ROI additions, derived from competitive analysis (Pcaptix), implementation readiness review, and documentation gap analysis. They should be sequenced first within their respective phases:

1. **★ Phase 12.1–12.2 — Documentation infrastructure & information architecture** — set up the docs system (mkdocs-material or equivalent), establish Diátaxis taxonomy, audit existing content, structure the sidebar for the eventual ~35-doc state. **Must land before Phase 8 starts producing doc deliverables**, otherwise new docs accumulate in the current ad-hoc structure and the overhaul gets harder. ~3–5 days.
2. **★ Phase 8.7 — Per-call asymmetry heuristics** — six new diagnostic checks (codec/ptime/payload/duration asymmetry, late media, one-sided silence). 3–4 days. Slots cleanly into the existing diagnostic alias system. **Highest analytical-feature ROI: industry-standard triage signals, free input data, immediate uplift to MCP `find_problems` tool.**
3. **★ Phase 8.6 expansion — quality timeline bump + `.sipnab` project file** — 1.5 days total. Match Pcaptix's 680ms quality intervals and trichotomy (OK/poor/uncertain), formalize the `.sipnab` directory convention.
4. **★ Phase 11 design** — write the design for cross-stream statistics and NISQA-based perceptual MOS *before* Phase 8 ships, but defer the build. Lets the design sit while higher-priority work proceeds; revisit priority after Phase 8.

All other items (Phase 11 build, Phase 12.3–12.7, waveform display, impairment detection beyond clipping, PDF export) are valuable but not urgent. They appear in the plan in ROI order so when bandwidth opens up there's a queue ready.

## Resolved Decisions

These were decided during planning review and supersede earlier v6 plan items.

- **gRPC is dropped from the roadmap.** The `grpc` feature flag listed in v6's README and feature matrix is removed. The structured-RPC slot it filled is split: REST + OpenAPI for humans/scripts/integrations (Phase 9), MCP for AI agents (Phase 8). gRPC adds tonic + prost + a `protoc` build dependency, complicates cross-builds, undermines the WASM browser story, and duplicates the REST surface. No concrete user has requested it. Revisit only if a specific gRPC use case emerges that REST and MCP cannot serve.
- **QUIC / HTTP/3 is not implemented inside sipnab.** nginx in front of sipnab handles HTTP/3 to the world; sipnab speaks HTTP/1.1 to nginx over loopback. sipnab's bottlenecks are CPU-bound (capture, parse), not network transport — switching to HTTP/3 changes nothing user-visible at sipnab's request rates. Revisit only if HEP-over-QUIC becomes a standard worth implementing (which is a Homer-project decision, not a sipnab one).
- **WebSocket and SSE are added to Phase 8.4** alongside MCP notifications, sharing the same broadcast-channel substrate. The cost of adding both once the substrate exists is trivial (~50 lines of axum each); the value of giving non-AI clients (curl, Grafana, custom scripts) access to the same live event stream is high.
- **Cap'n Proto / FlatBuffers are not added.** sipnab does not emit millions of events per second; protobuf-style binary serialization solves a problem sipnab does not have.
- **WebTransport is not added.** Browser support and the Rust server-side ecosystem are not yet mature enough. Revisit in 2027 or when `wtransport`-style crates stabilize.

### D20 — Infrastructure-Optional Integration

Any external infrastructure integration (metrics backends, event buses, tracing collectors, log aggregators, alerting systems) MUST follow this pattern. This is a load-bearing architectural rule that governs how sipnab plugs into the operator's existing stack without imposing new operational requirements.

**Requirements:**

1. **Compile-time opt-out.** Behind a Cargo feature flag (e.g. `nats`, `otel`, `api`/`metrics`) so users who'll never enable it pay zero binary size, zero transitive dependencies, and zero `cargo audit` surface area for the integration's libraries.
2. **Runtime opt-in.** Even when compiled in, activation requires an explicit CLI flag or env var (e.g. `--nats-url`, `--otel-endpoint`, `--metrics`). No flag = code path is dormant, no outbound connections attempted, no warnings logged about missing infrastructure.
3. **Failure-tolerant.** Infrastructure unavailability never blocks the capture pipeline. Push integrations (OTel, NATS) buffer-and-drop with bounded retries; pull integrations (Prometheus) simply expose endpoints and don't care if no one scrapes. Failure modes increment a counter (`dropped_*_total`) visible via `stats()` and the Prometheus endpoint.
4. **Operator owns the server side.** sipnab does not embed, supervise, install, or recommend a specific deployment of the backend. Documentation provides a one-line `docker run` example for testing and points to the backend project's docs for production deployment.

**Push vs pull semantics (worth being precise about):**

- **Pull integrations** (Prometheus `/metrics`): sipnab exposes an endpoint and waits. No outbound connection, no client lifecycle, no failure mode visible to sipnab. Works in locked-down DMZs where outbound connectivity is restricted. Dormant when nothing scrapes it (which is normal and silent).
- **Push integrations** (OTel OTLP, NATS): sipnab actively connects out to the configured endpoint. Has a connection lifecycle (initial connect, reconnect, exponential backoff). Failures are detectable and worth a single WARN log after a retry threshold (then silent — no log spam). Requires firewall rules to permit the outbound connection.

Both kinds are equally valid; the choice between them is dictated by the backend protocol, not by sipnab.

**Currently applied to:**

- Phase 5 — Prometheus endpoint (pull, behind `api` feature, activated by `--metrics`)
- Phase 9.2 — OpenTelemetry traces and metrics (push, behind `otel` feature, activated by `--otel-endpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT` env)
- Phase 10 — NATS event bus (push, behind `nats` feature, activated by `--nats-url`)
- Phase 4 (existing) — syslog alerting (push to local syslog daemon, activated by `--syslog`)

**Future integrations covered by this rule:** Loki log shipping, Kafka event publishing, OpenSearch indexing, OpsGenie/PagerDuty alerting, Datadog/New Relic agents, anything similar that comes up. New contributor adding integration X consults D20 first; the answer is always the same shape.

**Specifically excluded from this rule:** functionality that is intrinsic to sipnab's purpose, like the capture device or the SIP parser. D20 governs *integrations with external operator-owned infrastructure*, not core features.

### D21 — Capture Sources vs. Enrichment Sources

This decision governs the answer to "should sipnab support reading from X?" where X is some new protocol or service. The answer depends on what X delivers, not how popular X is.

**Capture sources** deliver `(packet_bytes, timestamp, link_type)` tuples that flow into the existing parse → dialog → RTP pipeline. They are alternative ways to get SIP and RTP packets to sipnab. Today: pcap file (`-I`), live interface (`-d`), HEP listener (`--hep-listen`). Future capture sources MUST deliver the same tuple shape; if they don't, they're not capture sources, they're something else.

**Enrichment sources** deliver structured non-packet data (traces, logs, control-plane events, CDR records) that *augments* sipnab's packet-level view with context it cannot derive from packets alone — B2BUA-internal routing decisions, channel state from a PBX's perspective, hangup causes from CDRs. Enrichment sources never feed the parser; they correlate to dialogs that already exist in the dialog store.

**Why this distinction matters:** without it, every "should sipnab read from X?" question gets relitigated as a generic plumbing question. With it, the answer is a mechanical check:

- Does X deliver SIP/RTP packets? → It's a capture source candidate. Evaluate against demand and standardization.
- Does X deliver structured non-packet data about SIP/RTP sessions? → It's an enrichment source candidate. Evaluate against the correlation model in a future enrichment phase.
- Does X deliver something else (raw network data that isn't SIP, generic metrics, application logs)? → It's not a sipnab feature. Tell the requester what tool actually fits.

**Capture source policy:** new capture sources are added only when (a) the source carries SIP/RTP packets in a standard or near-standard format and (b) a concrete deployment needs it. Non-standard packet transports (publishing raw SIP to NATS or Kafka subjects) are rejected — HEP exists specifically as the standard protocol for shipping captured SIP across hosts; alternative transports for HEP payload (HEP-over-NATS, HEP-over-WebSocket, HEP-over-QUIC) are acceptable when there's demand because they preserve the standard payload. OTel as a packet source is rejected categorically — OTel is not a packet protocol.

**Enrichment source policy:** enrichment is a separate feature category. It does not belong in the capture source enumeration in CLI (`-I`/`-d`/`--hep-listen`). When enrichment sources are added (likely Phase 12+), they get their own flag namespace (`--enrich-otel-endpoint`, `--enrich-ami <host>`, etc.) and feed a correlation layer that sits alongside the dialog store, not the parser.

**Currently rejected, with reasoning:**
- Raw SIP over NATS / Kafka / generic message buses — non-standard wire format. HEP is the standard.
- OTel as a packet source — wrong protocol category. OTel carries traces, not packets.
- gRPC streaming of pcap — same reason as NATS, plus all the gRPC reasons in the earlier decisions.

**Currently deferred (capture sources worth considering when triggered):** HEP-over-NATS, HEP-over-WebSocket, SIPREC SRS mode. Listed in the Future Considerations section.

**Currently deferred (enrichment sources for a later phase):** OTel trace consumption, Asterisk AMI / FreeSWITCH ESL event consumption, CDR ingestion. Listed in the Future Considerations section.

### D22 — Competitive Feature Borrowing Discipline

When other tools (Pcaptix, sngrep, sipgrep, Wireshark, commercial voice-quality analyzers like Sevana AQuA) ship features sipnab doesn't have, the question is not "should we have feature parity?" — it's "does this feature strengthen sipnab's identity, or push it toward becoming a clone?"

**Borrow when:**
- The feature is industry-standard and operators expect it (per-call asymmetry checks, perceptual MOS, quality timelines)
- The feature can be implemented cleanly within sipnab's existing architecture without bloating the core (regression analysis fits naturally; impairment detection requires new code)
- The feature has natural channels to existing surfaces (TUI badges, JSON output, MCP tools, REST endpoints) so it lights up multiple consumers at once
- The feature does not require sipnab to take on a different identity (becoming a desktop GUI, locking to one LLM vendor, etc.)

**Reject when:**
- The feature exists primarily because the other tool's UI demands it, not because it improves analysis quality
- Implementation requires a fundamental shift in sipnab's positioning (e.g., abandoning the TUI to chase desktop-app polish)
- A free implementation requires licensed crypto/codec libraries with restrictive terms (PESQ/POLQA — use ViSQOL or NISQA instead)
- The feature would tie sipnab to a single vendor's ecosystem (OpenAI-only LLM, one specific PCAP format, etc.) when generic alternatives exist

**Currently applied:** Phase 8.7 (per-call heuristics borrowed from Pcaptix), Phase 8.6 quality-timeline bump (matches Pcaptix's 680ms intervals), Phase 11 (cross-stream stats + perceptual MOS via NISQA, not via Sevana's licensed AQuA). Rejected: Pcaptix-style chat UI (MCP is the better abstraction), Qt desktop GUI (TUI/WASM is sipnab's positioning), OpenAI-only integration (MCP is provider-agnostic).

### D23 — Documentation as Tier-1 Deliverable

Documentation is not a post-hoc addition to a release — it's part of the deliverable. A feature without docs is incomplete and does not ship. This is the rule whether the new work is a single CLI flag or an entire phase.

**Requirements:**

1. **Docs land in the same PR as code.** A PR that adds a CLI flag without documenting it in `docs/cli-reference.md` and (if applicable) in the relevant tutorial / how-to / concept page does not get merged. Reviewers enforce this; CI catches the mechanical cases (every flag in `cli.rs` must appear in `cli-reference.md` — see Phase 12.7 quality tooling).
2. **Phases ship with their docs complete.** Each sub-phase in this plan has explicit docs deliverables. A phase is not "done" until those exist, not just the code.
3. **Information architecture is owned (Diátaxis framework — Phase 12.2).** Each new doc has a defined slot: tutorial, how-to, reference, or explanation. No new doc is added without classifying it; no doc straddles two categories.
4. **Versioned docs match released versions.** Each released version of sipnab has a corresponding pinned version of the docs site. Users on v0.3 see v0.3 docs by default; users on `main` see unreleased docs. Phase 12.1 sets up the versioning infrastructure (mike or equivalent).
5. **Quality is gated in CI.** Link checking, spell checking, "every CLI flag is documented," "every MCP tool is documented," "every public Rust API has rustdoc" all run in CI. Phase 12.7 specifies the tooling.

**Why this is a load-bearing rule:** the existing docs/ directory has 10 files, mostly reference. The roadmap (Phases 8–11) adds ~20+ new doc files. Without D23, those new docs accumulate in the same flat, no-IA structure that already doesn't scale, and the gap between "code shipped" and "users can use it" widens with every release. With D23, each phase's doc work is sized into the phase from the start, and the documentation system that Phase 12 builds catches the new content as it lands rather than being asked to retrofit it later.

**Specifically excluded from this rule:** internal design documents (`docs/superpowers/specs/`, `tasks/`), implementation plans (this document), and CHANGELOG entries — these are project-internal artifacts, not user-facing documentation, and follow different conventions.

### D24 — Tests Gate Phase Completion

A sub-phase is not "done" until its tests exist as committed code and pass on CI. Every code-bearing sub-phase in this plan ships a `**Tests — X.Y deliverables:**` block alongside its `**Gate**` and `**Docs**` blocks. The Tests block enumerates the concrete test files and the behavior each covers; signing off the gate requires those files to exist and `cargo test --features <relevant>` to be green.

**Requirements:**

1. **Tests are part of the same PR as the code they exercise.** A PR that adds or modifies behavior without adding or updating tests does not merge. Reviewers enforce relevance; CI enforces presence (the `tests/` test count never decreases between releases without an explicit "tests removed because feature removed" CHANGELOG entry).
2. **Every new behavior has at least one test that fails when the behavior breaks.** Coverage is per-behavior, not per-line. A function with three branches gets at least three assertions.
3. **Test types per code shape:**
   - **Pure functions / parsers** — unit tests in the same module's `#[cfg(test)] mod tests`, plus a fuzz target under `fuzz/fuzz_targets/` for any function consuming external bytes (SIP, RTP, HEP, MCP wire format, etc.).
   - **Stateful code** (dialog/stream stores, alert engine, event bus) — property tests using `proptest` or table-driven cases plus a Loom test where concurrency is involved. The 8.4a substrate is the canonical example.
   - **CLI / MCP / REST surfaces** — end-to-end tests in `tests/e2e/` using the actual binary (spawned via `assert_cmd` or `expectrl`) or the actual MCP client (`mcp-inspector` or a thin rmcp test harness). No mocking the wire protocol.
   - **Diagnostic checks** — unit tests with hand-crafted `SipDialog` + `RtpStream` fixtures covering positive cases, the negative ("not detected") case, and edge cases (single-leg call, zero packets, codec mismatch under each direction).
4. **Performance gates ship as `criterion` benchmarks**, not eyeballed timings. When a sub-phase has a perf criterion (e.g., 9.2's "regression > 5% fails CI"), the criterion bench is itself a gate deliverable that runs in CI.
5. **Test deliverables are sized into the phase estimate.** Phase 8/9/11 effort lines already account for test writing; per project convention test code averages ~50–80% of feature code by line count. If a sub-phase estimate is 3 days, expect ~1–1.5 days of that on tests.

**Why this is a load-bearing rule:** the gate criteria already include test-shaped statements ("X works", "Y returns expected output"). D24 makes explicit that satisfying those requires writing tests that exercise them, not just observing the behavior in a manual session. Every sub-phase's gate sign-off depends on a green CI run with the new tests in it. Without D24, gates degrade into "looked right when I tried it" — which is how regressions get shipped.

**Specifically excluded from this rule:** doc-only sub-phases (12.1 site infra, 12.2 IA, 12.3 tutorial writing, 12.5 concept pages, 12.6 cookbook, 12.7 marketing pages). Those have their own quality gates per D23 (link checker, spell checker, code-block validation, CLI/MCP coverage scripts). Code-bearing sub-phases are subject to D24 in full.

**Test inventory at start:** the v0.3 codebase ships ~1,300 passing tests across 17 test groups (verified `cargo test --features full` on the working tree). Each new sub-phase's Tests block adds to that count; CHANGELOG entries note the new test count per release.

---

## Scope

Add an `--mcp` mode to sipnab that exposes the existing read-only analysis surface (dialogs, streams, diagnostics, security findings, call reports) as **Model Context Protocol** tools, so a local AI agent (Claude Code, Claude Desktop, or any MCP-capable client) can drive sipnab as a debugging instrument against a live capture or a pcap file on a remote server.

MCP is treated as a **fourth output mode** alongside the existing TUI, `-N` CLI, and `--json` modes — not a new analysis subsystem. Tool handlers are thin wrappers over functions that already exist in `src/output/`, `src/sip/dialog_store.rs`, and `src/rtp/`. The capture pipeline, privilege model, and security guarantees are unchanged.

### Out of scope for Phase 8

- **MCP client functionality.** sipnab is the server. Any client behavior (calling out to other MCP servers) is deferred.
- **Mutating tools.** No tool starts/stops capture, modifies config, sends SIP, or writes to non-output paths. Capture lifecycle is owned by systemd / the CLI flags, not the LLM.
- **Audio extraction over the wire.** WAV bytes are too large for tool responses. `snapshot_pcap` writes to a server path; the agent fetches separately.
- **Replacing the REST API.** Phase 6's REST API and Phase 8's MCP coexist. They share the same axum stack when both are enabled.

---

## Threat Model Notes (additive to the v6 model)

MCP introduces one new attack surface and amplifies one existing one:

- **New: tool-call as a query channel.** An LLM with MCP access to sipnab on a debug target can read every Call-ID, every SIP body, every RTP SSRC. SIP carries DIDs, From/Contact URIs, sometimes `Authorization` digest material when intercepting registration traffic. **Treat MCP access as equivalent to having read access to the live SIP wire.** Authentication is therefore not optional past loopback.
- **Amplified: prompt injection via SIP content.** SIP From-display, User-Agent, and reason phrases can contain arbitrary UTF-8. An attacker who can place SIP traffic on a network sipnab is watching could inject text intended to manipulate the LLM consuming sipnab tool output. Mitigations are downstream of sipnab (the agent's prompt design), but sipnab MUST NOT add interpretation: pass values through verbatim, never instruct the LLM in tool descriptions to "trust" or "act on" content.

D-decisions referenced from v6: D15 (privilege drop), D16 (process isolation), D17 (defense-in-depth limits), D18 (localhost default), D19 (no key material in IPC).

---

## Phase 8 — MCP Server Mode

**Goal:** A local AI agent can drive sipnab against a live capture or pcap on a remote host using Model Context Protocol.
**Milestone:** `sipnab --mcp -d eth0 --mcp-bind 127.0.0.1:8731 --mcp-token-file /etc/sipnab/token` serves an MCP server that an agent on another host (via reverse proxy) can use to list dialogs, fetch call reports, and search SIP messages.
**Release target:** v0.4.0.

**Exit criteria — Phase 8 is done when:**
- [ ] `sipnab --mcp` starts a Model Context Protocol server using stdio transport
- [ ] `sipnab --mcp --mcp-transport http` starts a Streamable-HTTP MCP server reusing the existing axum stack
- [ ] All MCP tools are read-only with respect to capture state and the SIP wire — no tool mutates the dialog/stream/alert stores, no tool sends SIP. The single exception is `snapshot_pcap`, which writes captured packets to a configurable allowlist directory subject to size cap (`--mcp-snapshot-max-bytes`) and rate limit (`--mcp-snapshot-rate-per-min`)
- [ ] **MCP HTTP transport binds to localhost by default** (D18); non-loopback without bearer token refuses to start
- [ ] **MCP HTTP transport reuses the API rate limiter and `constant_time_eq` auth path** — no parallel implementations
- [ ] **MCP server respects privilege drop** — listener binds *after* `privilege::drop_privileges` (matching existing API pattern: `start_api_server` is invoked at `main.rs:839` for TUI mode and `:1130` for batch, both after the drop at `:439`). Default port 8731 is ≥ 1024 so the unprivileged sipnab user can bind it; non-loopback deployments must keep `--mcp-bind` ≥ 1024 or grant `CAP_NET_BIND_SERVICE` separately.
- [ ] **No MCP tool handler holds a `parking_lot::RwLock` guard across an `.await`** — verified by audit and a clippy lint where feasible
- [ ] **stdio transport: env_logger routed to stderr, never stdout** — verified by a test that runs `--mcp` with stdio and parses stdout as JSON-RPC for the full session without protocol corruption
- [ ] WASM build (`cargo build --target wasm32-unknown-unknown --no-default-features`) is unaffected — `mcp` and `mcp-http` features are mutually exclusive with `wasm`
- [ ] An end-to-end test using the official `mcp-inspector` tool against a stdio-spawned sipnab passes for all advertised tools
- [ ] An end-to-end test using a real Claude Code / Claude Desktop client against the HTTP transport completes a "find problems in this capture" workflow

---

### 8.0 — Foundational Cleanups (prerequisite to all of Phase 8)

Two cleanups land before any MCP work because every subsequent sub-phase builds on the cleaner base. These are not optional and not parallelizable with 8.1 — they go first.

**8.0a — Parse-path consolidation** (~1.5 days)

- [ ] **Audit the double-parse in batch+API mode.** Verified call chain today: `processor.process()` (`src/main.rs:1257`) does Ethernet/IP/TCP/UDP reassembly only — no SIP parsing. `process_parsed_packet()` (`:1296`) does the first SIP parse + `dialog_store.process_message` against the local store. `mirror_to_shared_stores()` (`:1326` invocation, `:2142` definition) does a second full SIP parse + a second `dialog_store.process_message` against the `Arc<RwLock<...>>` shared store. Result: every matching packet is parsed twice when `--api` is on in batch mode.
- [ ] **Refactor batch mode to share stores from the start**, mirroring the TUI mode pattern (which already passes `Arc<RwLock<...>>` between the processing thread and `start_api_server`). After the refactor: one parse per packet, regardless of how many output sinks are attached. The EventBus from 8.4a will subscribe off this single parse path.
- [ ] **Gate:** `cargo bench parser_bench` shows no regression in batch-without-API throughput, and shows the previous batch-with-API throughput approximately double (because the second parse is gone). An end-to-end test confirms `cargo run -- -I <pcap> --api :0 --json` produces JSON output identical to the pre-refactor output.

**8.0b — Mechanical log→tracing migration** (~1 day)

- [ ] **Add `tracing = "0.1"`** as an unconditional dep (lightweight facade). Add `tracing-log = "0.2"` for compatibility during the migration window.
- [ ] **Replace `log::error!`/`warn!`/`info!`/`debug!`/`trace!` with the `tracing::` equivalents** across all `.rs` files. The macros are drop-in compatible. No spans, no `#[instrument]`, no attributes added in 8.0 — the goal is purely "every log site is now a tracing site." Phase 9.2 layers on the actual span hierarchy.
- [ ] **Replace `env_logger::init()` with a `tracing-subscriber` initializer.** Default subscriber writes to stderr (preserving stdio MCP's "stdout is the JSON-RPC wire" invariant from gotcha #1). WASM build retains its existing `console_log` path; the WASM-specific subscriber is gated under `cfg(target_arch = "wasm32")`.
- [ ] **Gate:** `cargo build --features full` succeeds with no `log::*` macro calls in the codebase (`grep -rn '\blog::\(error\|warn\|info\|debug\|trace\)!' src/` returns zero hits, with allowance for the `log` re-export in `Cargo.toml` if any third-party dep uses it transitively). All existing test suites pass without modification.
- [ ] **Gate:** `cargo build --target wasm32-unknown-unknown --no-default-features` succeeds — the WASM build was the failure mode that previously made this migration scary; it is verified before 8.1 starts.

**Why 8.0 first:** every line of new MCP code in 8.1+ is written tracing-native; the parse path that 8.4a's EventBus subscribes to is single-pass; Phase 9.2 inherits a tracing-instrumented codebase and only needs to add spans + the OTLP exporter. Without 8.0, every later phase carries migration debt.

**Tests — 8.0a deliverables (D24):**
- [ ] `benches/parse_path.rs` — `criterion` benchmark comparing batch-with-API throughput before vs after the refactor; the gate's "approximately double" claim is a numeric assertion against a calibrated baseline, not hand-eyeballing
- [ ] `tests/integration/batch_api_parse_once.rs` — runs `sipnab -I tests/pcap-samples/<known>.pcap --api :0 --json` against a fixture; asserts JSON output is byte-identical to a golden file under `tests/golden/batch_api/`
- [ ] `tests/integration/single_parse_assertion.rs` — instruments `process_parsed_packet` with a per-call counter; asserts each Call-ID is parsed exactly once when `--api` is on in batch mode (catches future regressions of the double-parse)
- [ ] All pre-existing parser/dialog/stream test suites pass without modification (refactor is behavior-preserving; this is enforced by CI running the existing `cargo test --features full`)

**Tests — 8.0b deliverables (D24):**
- [ ] No new test files required — the migration is mechanical and the existing 1300+ tests prove behavioral equivalence across all output paths (TUI/CLI/JSON/API)
- [ ] CI gate `.github/workflows/no-log-macros.yml` — runs `! grep -rn '\blog::\(error\|warn\|info\|debug\|trace\)!' src/` (must exit non-zero, i.e., zero matches required)
- [ ] CI gate verifies `cargo build --target wasm32-unknown-unknown --no-default-features` succeeds (existing job; this gate is a regression check after the subscriber swap)
- [ ] CI gate verifies stdio MCP integrity — added in 8.1's Tests block; references this constraint so 8.0b can be reverified later

---

### 8.1 — Cargo.toml, Module Skeleton, Stdio Transport

Land the feature flags, module skeleton, and stdio MCP server with the three highest-value read-only tools. Stdio mode is the simplest path and lets the rest of the work proceed without HTTP plumbing.

- [ ] **Add dependencies (feature-gated):**
  ```toml
  rmcp = { version = "1", default-features = false, features = [
      "server", "transport-io", "macros", "schemars",
  ], optional = true }
  ```
  (`schemars` is re-exported by rmcp 1.x; do not add a separate `schemars` dependency.)
- [ ] **Add features:**
  ```toml
  mcp      = ["native", "dep:tokio", "dep:rmcp"]
  mcp-http = ["mcp", "api", "rmcp/transport-streamable-http-server"]
  full     = ["native", "tui", "tls", "hep", "api", "audio", "mcp-http"]
  ```
  `mcp` does **not** depend on `audio`. Phase 8.7's `one_sided_silence` asymmetry check requires decoded PCM samples; when `audio` is not compiled in, the check is omitted at runtime and the response carries `silence_unavailable: true` alongside the other five asymmetry signals. This preserves the D20 "compile-time opt-out" principle and keeps `--features mcp --no-default-features` viable for size-sensitive deployments. `mcp-http` deliberately depends on `api` so the axum stack is shared. `default` is unchanged (`["native", "tui", "audio"]`).
- [ ] **Update `deny.toml`:** verify rmcp's transitive dependencies (jsonwebtoken, oauth2, hyper, sse-stream, etc.) license under the existing allowlist; add `licenses.clarify` entries if needed.
- [ ] **Module skeleton at `src/mcp/`:**
  ```text
  src/mcp/
  ├── mod.rs        # cfg(feature = "mcp"), re-exports
  ├── server.rs     # SipnabMcp struct, #[tool_router] impl, ServerHandler impl
  ├── tools.rs      # Parameter structs (serde::Deserialize + schemars::JsonSchema)
  ├── shape.rs      # Result-shaping helpers (size caps, pagination cursors)
  └── transport.rs  # serve_stdio(); serve_http() gated on mcp-http
  ```
- [ ] **Wire `pub mod mcp;` in `src/lib.rs`** under `#[cfg(feature = "mcp")]`, paralleling the existing `#[cfg(feature = "api")] pub mod api;` pattern in `src/output/`.
- [ ] **Add CLI flags to `src/cli.rs` (under a new `// ── MCP ─────` section):**
  - `--mcp` (bool) — run as MCP server instead of TUI/CLI
  - `--mcp-transport <stdio|http>` (default `stdio`, requires `--mcp`)
  - `--mcp-bind <ADDR>` (default `127.0.0.1:8731`, requires `--mcp` and `--mcp-transport http`)
  - `--mcp-token <TOKEN>` (env `SIPNAB_MCP_TOKEN`, requires `--mcp`)
  - `--mcp-token-file <FILE>` — read token from file (preferred over env in systemd units)
  - `--mcp-redact-sip` (bool) — mask user-parts in From/To/Contact and Authorization lines in tool output
- [ ] **Update `Cli::validate`** to:
  - Reject `--mcp` combined with `--no-tui` set to false unless TUI feature is absent (MCP implies non-interactive)
  - Reject `--mcp` combined with `--api` on the same `--mcp-bind` (port conflict)
  - Require `--mcp-token` or `--mcp-token-file` when `--mcp-bind` is non-loopback
- [ ] **`Cli::warn_unimplemented_flags`:** add a one-line warning if `--mcp-redact-sip` is set without TLS keys present (redaction is best-effort, not security)
- [ ] **MCP tool description audit + CI lint** — write each `#[tool]` doc string to a description-only style: state what the tool returns, never instruct the LLM to "trust", "act on", "verify", or "ensure" anything about returned content (D22 prompt-injection rule). Add a CI lint pattern (`scripts/check-tool-descriptions.sh`) that greps `src/mcp/server.rs` for those imperative verbs inside `#[tool]` doc strings and fails the build on a hit. Document the convention in `docs/mcp-overview.md` so contributors know the rule before they add a tool.
- [ ] **Feature-combination CI matrix** — `.github/workflows/feature-matrix.yml` builds at minimum: each named feature individually (`mcp`, `mcp-http`, `api`, `tui`, `audio`, `tls`, `hep`, `wasm`), `--no-default-features` baseline, `full`, and the documented mutually-exclusive pairs as must-fail builds (`mcp + wasm`, `mcp-http + wasm`). Catches feature-graph drift introduced by any later phase.
- [ ] **Dispatch in `src/main.rs`** *after* CLI validation, after capture readiness, after privilege drop (matching the existing `--api` server start at line 2080):
  ```rust
  #[cfg(feature = "mcp")]
  if cli.mcp {
      let dialog_store = Arc::new(RwLock::new(DialogStore::new(
          cli.limit as usize, cli.rotate
      )));
      let stream_store = Arc::new(RwLock::new(StreamStore::new(
          cli.max_streams as usize
      )));
      // Spawn capture + mirror_to_shared_stores in a thread, like batch+api mode.
      // Then run MCP server on a dedicated thread with its own current_thread runtime.
      run_mcp_mode(cli, dialog_store, stream_store, /* ... */);
      return;
  }
  ```
- [ ] **Three v0.4.0 tools wired in `src/mcp/server.rs`:**
  - `list_dialogs(filter?, since?, until?, limit=50)` — wraps `DialogStore::iter()` + optional `FilterExpr::parse(filter).matches_dialog(...)`. Filter strings accept the existing DSL plus the named aliases (`problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`) via `crate::sip::dsl::expand_alias`.
  - `get_dialog_report(call_id, format="json"|"markdown"|"text")` — wraps `crate::output::generate_call_report` with the same `ReportFormat` enum that `--call-report` uses. JSON output is identical to `GET /v1/dialogs/:call_id/report`.
  - `find_problems(kinds?=["problems"], limit=50)` — convenience wrapper that runs `list_dialogs` with each named alias OR'd together. `kinds` defaults to `["problems"]` (the union alias). At 8.1 ship, supported `kinds` are the existing aliases (`problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`); the six asymmetry aliases (`codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`, `silent-leg`) activate automatically when 8.7 lands because the wiring goes through `expand_alias` — no Phase 8.1/8.3 code change required.
- [ ] **Stdio transport in `src/mcp/transport.rs::serve_stdio`:**
  ```rust
  pub async fn serve_stdio(server: SipnabMcp) -> anyhow::Result<()> {
      let transport = (tokio::io::stdin(), tokio::io::stdout());
      let service = server.serve(transport).await?;
      service.waiting().await?;
      Ok(())
  }
  ```
- [ ] **Stdio logger discipline (gotcha #1):**
  Before calling `serve_stdio`, re-init `env_logger` with `Builder::new().target(env_logger::Target::Stderr)` regardless of `RUST_LOG` config, and audit `src/capture/parse.rs` and `src/sip/parser.rs` for any `println!`/`eprintln!` (use `log::warn!` only).
- [ ] **Tool handlers MUST follow the lock pattern from `src/output/api.rs:370–402`:**
  ```rust
  // CORRECT
  let ds = state.dialog_store.read();
  let snapshot: Vec<DialogSummary> = ds.iter().filter(...).take(limit).map(into_summary).collect();
  drop(ds);                          // explicit drop
  Ok(CallToolResult::structured(...)) // .await-ing happens after drop
  ```
  Add a doc-comment on `SipnabMcp` enforcing this and add a `#[deny(clippy::await_holding_lock)]` at the module level.

**Gate — 8.1 is done when:**
- [ ] `cargo build --features mcp --no-default-features` succeeds
- [ ] `cargo build` (default features, no `mcp`) succeeds and binary size is unchanged ±50KB
- [ ] `cargo build --target wasm32-unknown-unknown --no-default-features` succeeds (no rmcp pulled in)
- [ ] `sipnab --mcp -I tests/pcap-samples/<known>.pcap` starts, accepts `initialize` JSON-RPC over stdio, and lists three tools
- [ ] `mcp-inspector` against the stdio binary lists `list_dialogs`, `get_dialog_report`, `find_problems` with valid input schemas
- [ ] Calling `list_dialogs` with `{"filter": "problems", "limit": 5}` returns up to 5 dialog summaries with the expected fields
- [ ] Calling `get_dialog_report` with a valid Call-ID and `format: "json"` returns content byte-identical to `--call-report <id> --json`
- [ ] Calling `get_dialog_report` with an unknown Call-ID returns a structured `McpError` (not a panic, not an empty result)
- [ ] **Stdio protocol integrity test:** spawn `sipnab --mcp -I <large.pcap>` with `RUST_LOG=trace`, send 100 tool calls over stdio, verify every line on stdout parses as valid JSON-RPC (no log lines bleed in)
- [ ] `cargo clippy --features mcp -- -D clippy::await_holding_lock` passes
- [ ] No new entries in `cargo audit` introduced by rmcp's dependency tree

**Tests — 8.1 deliverables (D24):**
- [ ] `tests/mcp/stdio_protocol.rs` — JSON-RPC stdio integrity: spawns `sipnab --mcp -I <pcap>` with `RUST_LOG=trace`, sends 100 tool calls over stdio, asserts every line on stdout parses as valid JSON-RPC (Gotcha #1 regression guard)
- [ ] `tests/mcp/tools_dispatch.rs` — invokes each of the three v0.4 tools with valid + invalid params, asserts response shape matches the documented schema, asserts unknown Call-ID returns a structured `McpError` (not a panic)
- [ ] `tests/mcp/tool_descriptions_lint.rs` — runs the imperative-verb regex from the description-audit subtask against `src/mcp/server.rs` doc strings; fails if any `#[tool]` doc contains "trust", "act on", "verify", or "ensure" (D22 prompt-injection rule, encoded as test)
- [ ] `tests/mcp/feature_matrix_smoke.rs` (a CI-driven manifest, not a single .rs file) — `.github/workflows/feature-matrix.yml` exercises each feature combo from D24's matrix and is itself the test artifact
- [ ] `cargo clippy --features mcp -- -D clippy::await_holding_lock` is run as a CI step (the gate already lists this; D24 names it as the test-equivalent for the lint-as-test pattern)
- [ ] `tests/mcp/inspector_e2e.rs` (or a CI shell job invoking the upstream `mcp-inspector` binary) — lists the three tools, calls each, validates schema. Output captured under `tests/snapshots/` via `insta`

**Docs — 8.1 deliverables:**
- [ ] Rustdoc on `src/mcp/{mod,server,tools,transport}.rs`
- [ ] `docs/mcp-overview.md` — what MCP is, why sipnab supports it, security model, transport choices
- [ ] `docs/mcp-tools.md` — tool reference for `list_dialogs`, `get_dialog_report`, `find_problems`: parameters, return shape, examples
- [ ] Update `docs/cli-reference.md` with the new `--mcp*` flags
- [ ] Update `README.md` Features section: "MCP server mode — drive sipnab from an AI agent"

---

### 8.2 — Streamable-HTTP Transport, Reusing the axum Stack

Add network transport so a remote agent can talk to sipnab on a debug target. This is the transport the original issue actually requires.

- [ ] **Implement `transport::serve_http`** behind `#[cfg(feature = "mcp-http")]`:
  - When `--api` is **not** set: bind a dedicated axum Router on `--mcp-bind` with the MCP service mounted at `/mcp` plus `/health`
  - When `--api` **is** set and `--mcp-bind` matches `--api` bind: mount MCP at `/mcp` on the existing `output::api::build_router` Router (extend `build_router` to take an optional MCP nested router)
  - When binds differ: run two independent axum servers in two threads (each with its own `current_thread` tokio runtime, matching `start_api_server` at `main.rs:2109`)
- [ ] **Reuse `output::api::parse_bind_addr`** for `--mcp-bind` parsing (`":8731"` shorthand, `"8731"` shorthand, full `addr:port`)
- [ ] **Reuse `output::api::guard()`** (`check_auth` + `check_rate_limit`) — wrap MCP requests in the same middleware. Token comparison MUST use `output::api::constant_time_eq`.
- [ ] **Bearer token resolution:** `--mcp-token` (CLI) > `--mcp-token-file` (file, trimmed) > `SIPNAB_MCP_TOKEN` env. Empty token after resolution is a startup error when bind is non-loopback.
- [ ] **TLS:** reuse `--api-tls-cert` / `--api-tls-key` flag pair when MCP shares the bind with `--api`. Independent TLS for MCP-only deployment is deferred to v0.5.
- [ ] **Non-loopback warning:** identical to api.rs behavior — log a WARNING when `--mcp-bind` is non-loopback without TLS, refuse to start when non-loopback without bearer token (D18 + new constraint specific to MCP given the data sensitivity).
- [ ] **Privilege drop sequencing (gotcha #2):**
  Spawn the MCP server thread *after* `privilege::drop_privileges` at `main.rs:439`, matching `start_api_server` (called at `main.rs:839` and `:1130`, both post-drop). The listener binds as the unprivileged sipnab user; this works because the default `--mcp-bind` port (8731) is ≥ 1024. Document this constraint in `transport.rs`. If a deployment needs sub-1024 binding, that is an nginx-front-end concern (see deployment doc), not a sipnab-process concern.
- [ ] **Recommended deployment: nginx in front.** Document this in `docs/mcp-deployment.md`: bind sipnab to `127.0.0.1:8731`, terminate TLS in nginx, do source-IP allowlist + bearer token passthrough at the proxy layer. This avoids root-bound 443 entirely.
- [ ] **systemd unit** `contrib/sipnab-mcp.service` (ships alongside existing `sipnab.service`):
  ```ini
  [Service]
  Type=simple
  User=root
  AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
  ExecStart=/usr/local/bin/sipnab \
      --mcp --mcp-transport http \
      --mcp-bind 127.0.0.1:8731 \
      --mcp-token-file /etc/sipnab/mcp.token \
      --user sipnab \
      -d eth0 --portrange 5060-5061
  NoNewPrivileges=true
  ProtectSystem=strict
  ProtectHome=true
  PrivateTmp=true
  CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
  Restart=on-failure
  RestartSec=5
  ```
- [ ] **Token file convention:** `/etc/sipnab/mcp.token`, mode 0600, owner root, generated by an `EnvironmentFile`-friendly contrib script `contrib/gen-mcp-token.sh`.
- [ ] **Token rotation policy (v0.4):** rotating either `--api-token-file` or `--mcp-token-file` requires a sipnab restart in v0.4. This is a documented limitation, not a runtime feature — sipnab loads the token once at startup. Hot-reload via `notify`-based filesystem watching is deferred to v0.5+ pending operator demand. Document the restart requirement in both `docs/mcp-deployment.md` and the existing `docs/api-deployment.md` so operators don't discover it in production.

**Gate — 8.2 is done when:**
- [ ] `sipnab --mcp --mcp-transport http -I <pcap>` starts and serves `/health` on `127.0.0.1:8731` returning `200 ok`
- [ ] MCP `initialize` over Streamable HTTP succeeds against a Claude Desktop / Claude Code client pointed at `http://127.0.0.1:8731/mcp` with the bearer token configured
- [ ] `sipnab --mcp --mcp-bind 0.0.0.0:8731` (no token) **refuses to start** with a clear error referencing D18
- [ ] `sipnab --mcp --mcp-bind 0.0.0.0:8731 --mcp-token-file /tmp/tok` (no TLS) **starts with a WARNING** about cleartext non-loopback bind
- [ ] Request without `Authorization: Bearer <token>` → 401
- [ ] Request with wrong token → 401, and timing analysis on 1000 requests shows no measurable difference between "wrong token, right length" and "wrong token, wrong length" (constant-time comparison)
- [ ] 150 requests/sec from a single source IP → at least 50 receive 503 (rate limit shared with `--api`)
- [ ] Running `--mcp --mcp-bind 127.0.0.1:8731 --api :8080` simultaneously: both endpoints work, neither interferes
- [ ] Running `--mcp --mcp-bind 127.0.0.1:8080 --api :8080` (same port) is rejected at validation time
- [ ] `systemctl start sipnab-mcp.service` on a Debian Bookworm test VM brings sipnab up, drops privileges to `sipnab`, accepts MCP requests, and stops cleanly on `systemctl stop`
- [ ] Privilege check: `ps -o user,pid,comm` shows the running daemon as user `sipnab`, not root, after startup

**Tests — 8.2 deliverables (D24):**
- [ ] `tests/mcp/http_auth.rs` — covers the gate criteria as numeric assertions: 401 on missing/wrong token; constant-time comparison verified by timing histogram over 1000 requests with same-length and different-length wrong tokens (assertion: median delta < 1 µs)
- [ ] `tests/mcp/http_bind_validation.rs` — `--mcp-bind 0.0.0.0:8731` without token refuses to start (process exits non-zero, stderr references D18); same bind with token starts but logs a WARNING about cleartext non-loopback
- [ ] `tests/mcp/http_rate_limit.rs` — 150 requests/sec from one IP receives ≥ 50 503s; rate limiter shared with `--api` (verified by alternating `/v1/dialogs` and `/mcp` requests counting against the same bucket)
- [ ] `tests/mcp/coexist_with_api.rs` — `--mcp --mcp-bind 127.0.0.1:8731 --api :8080` simultaneously: both endpoints respond; same-port `--mcp-bind 127.0.0.1:8080 --api :8080` is rejected at validation time
- [ ] `tests/integration/systemd_smoke.rs` (or a CI shell job) — on a Debian Bookworm test VM (or container), `systemctl start sipnab-mcp.service` brings sipnab up, `ps -o user,pid,comm` shows non-root, accept MCP request, `systemctl stop` exits cleanly
- [ ] `tests/mcp/token_rotation_doc.rs` — asserts that `docs/mcp-deployment.md` and `docs/api-deployment.md` both contain the literal string "rotation requires restart" (catches D24-required documentation regressions)

**Docs — 8.2 deliverables:**
- [ ] `docs/mcp-deployment.md` — deployment guide: systemd setup, token file generation, nginx reverse proxy with TLS, source-IP allowlist, troubleshooting
- [ ] `contrib/sipnab-mcp.service` with documentation comments
- [ ] `contrib/gen-mcp-token.sh` token generation script
- [ ] `contrib/nginx-sipnab-mcp.conf` example reverse proxy config
- [ ] Update `docs/mcp-overview.md` security model section with the deployment recommendations

---

### 8.3 — Full Read-Only Tool Surface

Add the remaining read-only tools that round out the agent's debugging vocabulary. Each tool wraps existing functions; the work is parameter shaping and result bounding.

- [ ] **`get_dialog(call_id, max_messages=100, cursor=null)`** — full dialog including all SIP messages, paginated. Wraps `DialogStore::get` + iteration over `dialog.messages`. Cursor is the message index of the next page.
- [ ] **`get_message(call_id, index)`** — single SIP message with full headers and body. Wraps existing `crate::output::json::message_to_json`.
- [ ] **`render_ladder(call_id, format="markdown"|"text")`** — call flow ladder. v0.4 implementation: delegate to `generate_call_report` with `ReportFormat::Markdown` or `Text` (already produces ladder-shaped output). Rich SVG/HTML ladder is deferred to v0.5.
- [ ] **`rtp_stats(call_id)`** — RTP quality across all streams associated with the dialog. Wraps `StreamStore::iter().filter(associated_dialog == call_id)` and `crate::output::json::stream_to_json`. Returns codec, MOS, jitter, loss%, packet count, ssrc list, plus `crate::rtp::diagnosis::diagnose_media` results.
- [ ] **`search_messages(query, since=null, until=null, limit=50)`** — substring match over SIP method, status, From, To, User-Agent, and body across all dialogs. Returns `(call_id, message_index, snippet)` triples. Wraps the same iteration the `--filter` CLI path uses.
- [ ] **`tail_dialogs(cursor=null, limit=50)`** — incremental fetch of dialogs updated since a cursor. Cursor is an opaque RFC 3339 timestamp string (the `updated_at` of the last dialog returned). Lets a polling agent track changes without re-reading everything.
- [ ] **`tail_dialogs` post-EOF semantics:** when the capture source is a finished pcap (`-I` mode), the response envelope carries `source_exhausted: true` once all events have been delivered, and a one-shot `sipnab/source_exhausted` MCP notification fires the first time the source ends. Subsequent `tail_dialogs` calls continue to return `source_exhausted: true` with empty `dialogs` arrays. Prevents an agent from polling a finished source forever.
- [ ] **`security_findings(kinds?=["scanner","reg_flood","digest_leak","fraud","stir_shaken"], since=null, limit=50)`** — recent findings from the existing security detectors. **Prerequisite:** `AlertEngine` (`src/security/alerting.rs:118`) currently retains *only* the per-(IP, rule) cooldown map (`:122`); there is no findings history. Phase 8.3 must add a `FindingsHistory` ring buffer to `AlertEngine` as a discrete sub-task — see new task immediately below.
- [ ] **`AlertEngine::FindingsHistory` (new sub-task — prerequisite for `security_findings`):**
  - `Finding` struct: `{rule_name: String, src_ip: IpAddr, detail: String, timestamp: DateTime<Utc>, call_id: Option<String>}`. Captured in `AlertEngine::fire` *after* the cooldown check passes (so deduplicated findings aren't double-counted)
  - Bounded `VecDeque<Finding>`, default capacity 1000, configurable via `--mcp-findings-retain <N>` (Open Question #3). Oldest-evicted-first
  - In-memory only; not persisted across restart. Document this — operators wanting durable history should rely on the syslog/exec sinks, which already cover that case
  - Read API on `AlertEngine`: `iter_findings(kinds: &[&str], since: Option<DateTime<Utc>>, limit: usize) -> Vec<&Finding>`
  - Apply the same `truncate_string` capping from 8.3 when `detail` is large (some scanner findings carry full SIP fragments)
  - Mirror to REST as `GET /v1/security/findings` — the data is now retained anyway, and non-MCP consumers (Grafana, fail2ban dashboards) get it for free
  - **Gate addition:** unit test that fires 2000 findings against a 1000-cap history confirms exactly 1000 retained (most recent), with FIFO eviction order; thread-safety test confirms concurrent `fire()` and `iter_findings()` do not deadlock
- [ ] **`snapshot_pcap(filter?, call_id?, output_path)`** — write a filtered subset of captured packets to `output_path` on the *server* filesystem, return the path and packet count. Reuses `crate::capture::PcapWriter`. Path is restricted to a configurable allowlist directory (`--mcp-snapshot-dir`, default `/var/lib/sipnab/snapshots`), and refuses paths containing `..` or absolute paths outside the allowlist.
- [ ] **`snapshot_pcap` resource limits:** new flags `--mcp-snapshot-max-bytes <N>` (default 100 MB) caps the size of a single snapshot output file — writing stops at the cap with a structured error and the partial file is unlinked. `--mcp-snapshot-rate-per-min <N>` (default 6) rate-limits snapshot calls per token using the same token-bucket pattern as the API rate limiter. Without these, a misbehaving agent can fill the snapshot directory in seconds.
- [ ] **`stats()`** — single-shot aggregate counters: dialog count, stream count, orphaned stream count, alert counts by kind. Equivalent to `GET /v1/stats` from the REST API.
- [ ] **Result-bounding helpers in `src/mcp/shape.rs`:**
  - `truncate_string(s, max_chars)` — for SIP body and snippet returns
  - `cap_messages(msgs, limit)` — with a `truncated: true, total: N` envelope
  - `redact_user_part(uri)` — applied when `--mcp-redact-sip` is set, masking the user-part of a `sip:` URI
- [ ] **Bound every response by default** (gotcha echo from earlier discussion):
  - `list_dialogs` / `tail_dialogs` / `search_messages` default `limit=50`, hard cap `1000`
  - `get_dialog` default `max_messages=100`, hard cap `1000`
  - SIP body in `get_message` and `search_messages` snippets capped at 4096 bytes
  - `render_ladder` markdown/text capped at 64 KB; if larger, return a `truncated: true` flag with a hint to use `snapshot_pcap` and analyze locally

**Gate — 8.3 is done when:**
- [ ] All 8 additional tools registered and described in tool list
- [ ] `get_dialog` with cursor pagination returns sequential message slices summing to the full dialog
- [ ] `render_ladder` markdown output is byte-identical to `sipnab --call-report <id> --markdown` for the same dialog
- [ ] `rtp_stats` MOS values match `--call-report --json` for the same dialog within floating-point tolerance
- [ ] `search_messages` with a query that matches a known UA string returns the expected dialogs
- [ ] `tail_dialogs` called twice with the second call's cursor set to the first call's last `updated_at` returns no overlap
- [ ] `snapshot_pcap` with `output_path: "/etc/passwd"` returns an error (path not in allowlist), file is not touched
- [ ] `snapshot_pcap` with a valid path produces a pcap that opens in Wireshark and contains exactly the expected packets
- [ ] `--mcp-redact-sip` causes `From: sip:1234567890@example.com` to be returned as `From: sip:**********@example.com`
- [ ] All tool responses respect their hard caps when called with a deliberately large dataset
- [ ] No tool exposes any TLS/SRTP key material in any field (D19) — verified by grep on a 1-hour test capture with `--tls-key` active

**Tests — 8.3 deliverables (D24):**
- [ ] `tests/mcp/get_dialog_pagination.rs` — `get_dialog` cursor pagination returns sequential message slices summing to the full dialog; cursor at end returns empty page with `complete: true`
- [ ] `tests/mcp/render_ladder_identity.rs` — markdown output is byte-identical to `sipnab --call-report <id> --markdown` for a fixture dialog (golden file)
- [ ] `tests/mcp/rtp_stats_identity.rs` — MOS values match `--call-report --json` within `f64::EPSILON * 4`
- [ ] `tests/mcp/search_messages.rs` — substring queries against fixture dialogs return expected `(call_id, message_index, snippet)` triples; snippet capping verified at 4096 bytes
- [ ] `tests/mcp/tail_dialogs.rs` — second call with the first call's last `updated_at` cursor returns no overlap; `source_exhausted: true` flag fires after pcap EOF and persists; one-shot `sipnab/source_exhausted` notification fires exactly once
- [ ] `tests/security/findings_history.rs` — fires 2000 findings against a 1000-cap `AlertEngine::FindingsHistory`; asserts exactly 1000 retained, FIFO eviction order; concurrent `fire()` + `iter_findings()` does not deadlock (8.3 gate item, formalized as D24 test)
- [ ] `tests/mcp/snapshot_pcap_security.rs` — `output_path: "/etc/passwd"` returns structured error and does not touch the file; valid path produces a pcap that round-trips through `pcap-file` parser
- [ ] `tests/mcp/snapshot_pcap_limits.rs` — exceeding `--mcp-snapshot-max-bytes` truncates with error and unlinks partial file; exceeding `--mcp-snapshot-rate-per-min` returns 429-equivalent for the next call within the window
- [ ] `tests/mcp/redact_sip.rs` — `--mcp-redact-sip` masks user-parts in `From:`/`To:`/`Contact:`/`Authorization:` lines verbatim; assertion is byte-comparison against expected redacted forms
- [ ] `tests/mcp/response_caps.rs` — every tool response respects its hard cap when called against a deliberately oversized fixture (10K dialogs, 100KB body)
- [ ] `tests/mcp/no_key_material_leak.rs` — runs against a fixture pcap with `--tls-key`; greps every tool response for any byte sequence in the keylog; asserts zero matches (D19 enforcement)

**Docs — 8.3 deliverables:**
- [ ] Update `docs/mcp-tools.md` with all eight new tools
- [ ] `docs/mcp-agent-cookbook.md` — recipes for common debugging workflows: "find calls with one-way audio in the last 5 minutes", "extract pcap for a specific Call-ID and download it", "tail problems as they happen", "diagnose a customer's complaint by Call-ID"
- [ ] Update `docs/security-model.md` (or create) with the snapshot path allowlist semantics

---

### 8.4a — Event Bus Substrate (feature-gated)

Move from polling (`tail_dialogs`) to push, by adding a feature-gated broadcast substrate that tokio-world sinks (MCP, WebSocket, SSE, future NATS) subscribe to. **The existing `EventExecEngine::fire_dialog_event` / `fire_quality_event` synchronous direct-call path is preserved** — exec hooks continue to work in the default build with no tokio runtime. The substrate is constructed only when at least one of `api`/`mcp`/`mcp-http` is compiled in, so the default build's tokio-free invariant holds.

- [ ] **Substrate is feature-gated, not universal.** Add `pub mod event_bus;` under `#[cfg(any(feature = "api", feature = "mcp"))]`. When the bus exists, the parse path emits an `Event` to both: (a) the existing synchronous exec dispatch (unchanged), and (b) `EventBus::publish(event)`. When the bus doesn't exist (default build, no `api`, no `mcp`), only the synchronous exec dispatch fires.
- [ ] **Sink trait for tokio-world consumers:**
  ```rust
  #[cfg(any(feature = "api", feature = "mcp"))]
  pub trait EventSink: Send + Sync {
      async fn on_event(&self, event: &Event);
  }
  ```
  `McpSink`, `WsSink`, `SseSink` (and future `NatsSink`) implement this trait. `ExecSink` does **not** — exec keeps its existing direct-call path because there's no benefit to routing it through an async channel and forcing tokio into the default build.
- [ ] **Central broadcast channel:** `tokio::sync::broadcast::channel(capacity)` carrying a compact `Event` enum (`DialogChanged { call_id, state, ts }`, `QualityDrop { call_id, ssrc, mos, ts }`, etc.). Capacity is bounded (default 1024).
- [ ] **Lag accounting (per-subscriber, not sender-side):** `tokio::sync::broadcast` does not drop events at the sender — slow receivers see `RecvError::Lagged(n)` and skip ahead in the ring buffer. Each sink tracks its own lag count; the metric is `dropped_events_total{sink="<name>"}` exposed via `stats()` and Prometheus. There is no global "drop oldest at sender" counter because that's not what the channel does. Each sink's receive loop must handle `Lagged(n)` by incrementing its counter and continuing — never panicking, never blocking the sender.
- [ ] **Sink registration:** `EventBus::subscribe() -> broadcast::Receiver<Event>` is the universal entry point. MCP/WebSocket/SSE handlers each get their own receiver from the same sender.
- [ ] **Reuse `--quality-threshold`** for the quality-event firing condition — no new threshold flag.
- [ ] **Sinks are independent:** removing one (no MCP subscribers, no WebSocket connections) does not stop the others or the existing synchronous `--on-dialog-exec`.

> *Parse-path consolidation (the prerequisite that makes the substrate's per-sink cost zero at the parse layer) is now Phase 8.0 — see above.*

**Gate — 8.4a is done when:**
- [ ] Default build (`cargo build`, no `api`, no `mcp`) does not pull in tokio and exec hooks fire identically to pre-8.4 behavior — verified by an integration test that runs `--on-dialog-exec` with the default feature set
- [ ] `cargo build --features api` constructs the EventBus and the existing API endpoints continue to work; no observable behavior change to existing API consumers
- [ ] `dropped_events_total{sink="..."}` accurately reflects per-subscriber lag under a 10K events/sec stress test, with a deliberately slow subscriber demonstrating non-zero lag while a fast subscriber stays at zero
- [ ] **Loom-based concurrency test** for the parking_lot-guard-across-await invariant (modeled with `loom::sync::RwLock` standing in for `parking_lot::RwLock`) completes every interleaving without deadlock for two concurrent MCP tool handlers + capture thread + broadcast sender
- [ ] Existing `--on-dialog-exec` and `--on-quality-exec` continue to work alongside any tokio-world sink; their direct-call path is unaffected by bus presence

**Tests — 8.4a deliverables (D24):**
- [ ] `tests/event_bus/no_tokio_in_default.rs` — compile-time assertion (using `cargo build --no-default-features --features audio` plus a runtime check on `cargo tree`) that the binary built with the default feature set does not pull in tokio. ExecSink integration test runs in this build configuration to prove the synchronous direct-call path is preserved.
- [ ] `tests/event_bus/feature_gate.rs` — confirms `pub mod event_bus` only exists under `cfg(any(feature="api", feature="mcp"))` via a build-time test
- [ ] `tests/event_bus/lag_per_subscriber.rs` — 10K events/sec stress test with two subscribers, one slow (artificial 10ms sleep per receive), one fast; asserts `dropped_events_total{sink="slow"} > 0` and `dropped_events_total{sink="fast"} == 0`
- [ ] `tests/event_bus/loom_concurrency.rs` — Loom test under `cfg(loom)` modeling two concurrent MCP tool handlers + capture thread + broadcast sender, all using `loom::sync::RwLock`. Every interleaving completes without deadlock. Run via `RUSTFLAGS="--cfg loom" cargo test --test loom_concurrency` in CI.
- [ ] `tests/event_bus/exec_sink_unaffected.rs` — fires 1000 dialog events with both an active broadcast bus and the existing `--on-dialog-exec` configured; asserts the exec sink receives every event regardless of broadcast subscriber state (no coupling)

**Docs — 8.4a deliverables:**
- [ ] `docs/event-bus.md` — substrate architecture, sync/async sink split, lag semantics, why ExecSink stays synchronous
- [ ] Rustdoc on `src/output/event_bus.rs` documenting the cfg-gated construction

---

### 8.4b — Sinks: MCP Notifications + WebSocket + SSE

Three consumer surfaces wired to the 8.4a substrate. Each sink is a thin wrapper that implements `EventSink` and serializes to its native wire format. **Per-subscriber filtering is receiver-side**, not sender-side, because `tokio::sync::broadcast` semantics require it — each receive loop applies its own filter against `Event` before forwarding.

#### MCP notifications

- [ ] **MCP notifications** — emit `notifications/resources/updated` for the affected dialog resource URI, plus a custom `sipnab/dialog_event` notification carrying a compact summary (Call-ID, new state, timestamp). Compact, not full dialog — clients can call `get_dialog` if they want detail.
- [ ] **Resource URIs:** `sipnab://dialog/{call_id}` and `sipnab://stream/{ssrc_hex}` exposed via MCP `resources/list` and `resources/read`. Reading a dialog resource is equivalent to calling `get_dialog_report(call_id, format="json")`.
- [ ] **Subscriptions:** support `resources/subscribe` so clients can opt into per-resource updates instead of the firehose.
- [ ] **Per-subscriber filtering:** dialog/stream filters narrow what each subscriber forwards downstream. Filter evaluation runs in the receive loop (receiver-side), since `tokio::sync::broadcast` delivers the same value to every receiver. The filter is "post-receive, pre-forward" — events that don't match are dropped at the sink boundary, never reaching the client.

#### WebSocket endpoint (gated on `mcp-http` or `api`)

- [ ] **`GET /v1/stream` (WebSocket upgrade)** mounted on the existing axum Router (the same one that hosts `--api` and `--mcp` HTTP). Reuses the existing bearer-token auth and rate limiter from `output::api`.
- [ ] **Wire format:** NDJSON event objects, one per WebSocket message. Schema versioned (`{"schema_version": 1, "event": "dialog_changed", "call_id": "...", ...}`).
- [ ] **Query-string filters:** `?call_id=<pattern>`, `?event=dialog_changed,quality_drop`, `?from=<regex>`. Filters are evaluated receiver-side in each WebSocket task before forwarding to its client (same constraint as MCP per-subscriber filtering — broadcast semantics require it).
- [ ] **Backpressure handling:** if a client cannot keep up (TCP send buffer full), close the connection cleanly with a 1011 status and increment `dropped_subscribers_total`. Do not block the broadcast sender.
- [ ] **Heartbeat:** ping frame every 30 seconds; close the connection if no pong response in 60 seconds.
- [ ] **Max concurrent WebSocket connections** — share the existing `--api-max-conn` limit; deny new upgrades with 503 when at capacity.

#### SSE endpoint (gated on `mcp-http` or `api`)

- [ ] **`GET /v1/events` (Server-Sent Events)** mounted on the same axum Router. Same auth, same rate limiter.
- [ ] **Wire format:** standard SSE `event:`/`data:` framing, one event per SSE message, JSON payload identical to the WebSocket NDJSON shape.
- [ ] **Query-string filters:** identical to the WebSocket endpoint, so clients can switch transports without changing their filter logic.
- [ ] **Auto-reconnect support:** include the standard `id:` field for browser EventSource auto-reconnect with `Last-Event-ID` resume. Cursor stored as the broadcast channel sequence number.
- [ ] **Heartbeat:** SSE comment line `: ping\n\n` every 30 seconds to keep proxies from idle-closing the connection.
- [ ] **MIME and headers:** `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no` (disable nginx response buffering for live streaming).

**Gate — 8.4b is done when:**

*MCP notifications:*
- [ ] An MCP client subscribed to `sipnab://dialog/<call_id>` receives a `notifications/resources/updated` within 100ms of that dialog transitioning state
- [ ] An MCP client receives a `sipnab/dialog_event` notification when any new dialog completes, payload contains `call_id`, `state`, `timestamp`
- [ ] Quality notifications fire for streams crossing `--quality-threshold` MOS downward, exactly once per crossing
- [ ] With 100 simultaneous MCP subscribers and 1000 dialog events/sec, no MCP server crash, no main thread starvation

*WebSocket:*
- [ ] `wscat -H "Authorization: Bearer $TOKEN" -c ws://127.0.0.1:8080/v1/stream` connects and receives NDJSON events
- [ ] Query-string filter `?event=quality_drop&call_id=abc.*` narrows the stream to only quality-drop events whose Call-ID matches
- [ ] A slow client (intentionally never-reads) gets disconnected within 5 seconds with status 1011, broadcast sender does not block
- [ ] Heartbeat keeps an idle connection alive for at least 10 minutes
- [ ] 101st simultaneous WebSocket connection (with `--api-max-conn 100`) gets 503 on upgrade

*SSE:*
- [ ] `curl -N -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/events` streams events with proper SSE framing
- [ ] Browser `EventSource` auto-reconnects after a network drop and resumes from the last seen `id:` (verified with Chrome DevTools)
- [ ] SSE through a default-config nginx reverse proxy delivers events with no buffering delay (verified with `X-Accel-Buffering: no`)
- [ ] Heartbeat `: ping` lines arrive every 30 seconds when no real events are flowing

**Tests — 8.4b deliverables (D24):**
- [ ] `tests/mcp/notifications_delivery.rs` — MCP client subscribed to `sipnab://dialog/<call_id>` receives `notifications/resources/updated` within 100ms of state transition (asserted via deadline)
- [ ] `tests/mcp/notifications_quality.rs` — quality notification fires exactly once per `--quality-threshold` downward crossing (asserted by counting fires across a fixture stream that crosses the threshold three times)
- [ ] `tests/mcp/notifications_subscriber_isolation.rs` — 100 simultaneous MCP subscribers + 1000 dialog events/sec; per-subscriber filter narrows correctly; one slow subscriber gets `Lagged(n)` while fast subscribers stay current
- [ ] `tests/websocket/stream_basic.rs` — `wscat`-equivalent client connects with bearer token, receives NDJSON; query-string filter `?event=quality_drop&call_id=abc.*` narrows correctly
- [ ] `tests/websocket/backpressure.rs` — slow client (never reads) is disconnected within 5s with 1011; broadcast sender does not block (proved by other clients still receiving events during the disconnect)
- [ ] `tests/websocket/heartbeat.rs` — idle connection survives 10 minutes with 30s ping/pong; missing pong for 60s closes the connection
- [ ] `tests/websocket/connection_cap.rs` — 101st connection with `--api-max-conn 100` gets 503
- [ ] `tests/sse/stream_basic.rs` — `curl -N` receives properly framed `event:` / `data:` / `id:` lines; nginx-buffered proxy test asserts `X-Accel-Buffering: no` is emitted
- [ ] `tests/sse/auto_reconnect.rs` — `EventSource`-equivalent client (using a pure-Rust SSE client crate) drops mid-stream, reconnects with `Last-Event-ID`, resumes from the stored cursor without duplicates and without gaps
- [ ] `tests/sse/heartbeat.rs` — `: ping` comment lines arrive every 30s when no real events flow

**Docs — 8.4b deliverables:**
- [ ] Extend `docs/event-bus.md` (created in 8.4a) with the comparison table: MCP / WebSocket / SSE / `--on-dialog-exec` — when to use which
- [ ] Update `docs/mcp-tools.md` with the resource URI scheme and subscription flow
- [ ] `docs/mcp-notifications.md` — push vs poll, when to use which
- [ ] `docs/websocket-stream.md` — endpoint reference, filter syntax, example clients (wscat, JavaScript, Python `websockets`)
- [ ] `docs/sse-stream.md` — endpoint reference, browser EventSource example, curl pipeline examples, nginx config notes

---

### 8.5 — HEP Source Mode and Multi-Source Operation

Add the third capture source so an MCP-driven agent can query a Homer-fed view.

- [ ] **`sipnab --mcp --hep-listen 0.0.0.0:9060`** — combine MCP server with HEP receiver. Existing CaptureSource::Hep path (already in `main.rs:198`) requires no MCP-specific changes; this gate verifies the integration works.
- [ ] **Document the topology:** edge servers send HEP to a central host, central host runs `sipnab --mcp --hep-listen ...`, agent queries the central host. This is the natural "fleet observability for an AI agent" pattern for a CLEC.
- [ ] **`sipnab --mcp -I <pcap>` post-mortem mode:** when source is a file, `tail_dialogs` and notifications behave as expected during the file replay, then the server stays alive for query-only access after replay completes (instead of exiting). Add `--mcp-keep-alive` flag (default true in MCP mode, false elsewhere) to control this.
- [ ] **Capture source identification in `stats()`:** report the active source (`{type: "live", device: "eth0"}`, `{type: "file", path: "/tmp/x.pcap"}`, `{type: "hep", bind: "0.0.0.0:9060"}`) so the agent knows what it's looking at.

**Gate — 8.5 is done when:**
- [ ] `sipnab --mcp --hep-listen 127.0.0.1:9060` accepts HEP packets from a sender (use `sipgrep --hep-send` or `kamailio` siphash test data) and tools return the dialogs
- [ ] `sipnab --mcp -I <pcap>` after pcap EOF still responds to MCP tool calls (does not exit)
- [ ] `stats()` correctly reports the active source type for each of the three modes

**Tests — 8.5 deliverables (D24):**
- [ ] `tests/mcp/hep_listen.rs` — `--mcp --hep-listen 127.0.0.1:9060` accepts HEP from a fixture sender (`sipgrep --hep-send` or a Rust-side HEP synthesizer), and tools return the resulting dialogs
- [ ] `tests/mcp/post_mortem_pcap.rs` — after pcap EOF, `tail_dialogs` returns `source_exhausted: true` and remaining tools (`list_dialogs`, `get_dialog_report`, `rtp_stats`) continue to respond identically
- [ ] `tests/mcp/source_identification.rs` — `stats()` reports the active source as `{type, ...}` for each of live/file/hep modes (table-driven test across all three)

**Docs — 8.5 deliverables:**
- [ ] `docs/mcp-hep-deployment.md` — central HEP collector + MCP topology, configuring edge senders, scaling considerations
- [ ] Update `docs/mcp-deployment.md` with the post-mortem pcap workflow

---

### 8.6 — Polish, Demos, Release

Wrap-up tasks tying Phase 8 into the v0.4.0 release. Two ★ priority items added from competitive analysis (Pcaptix benchmark): the quality-timeline-resolution bump and the `.sipnab` project file format.

**★ Quality timeline upgrade (priority):**
- [ ] **Bump `QualityInterval` resolution** from the current 1-second window to **680 ms**, matching Pcaptix's interval length so cross-tool comparisons line up. Add the change behind `--rtp-interval-ms <N>` (default 680, override allowed for backwards compatibility with existing `--rtp-interval` callers that expect seconds).
- [ ] **Trichotomy classification** — extend `QualityInterval` with a `status: "ok" | "poor" | "uncertain"` field. Thresholds (configurable via `[limits]` in TOML config):
  - `ok` — MOS ≥ 4.0, loss < 1%, jitter < 30ms
  - `poor` — MOS < 3.0, OR loss > 5%, OR jitter > 80ms
  - `uncertain` — between thresholds, OR fewer than 10 packets in the interval
- [ ] **Surfaces:** include `status` in `QualityIntervalJson` (existing schema field, backwards compatible since it's additive); render as a colored bar in the TUI stream detail view; expose via MCP `rtp_stats` tool from Phase 8.3.

**★ `.sipnab` project file format (priority):**
- [ ] **Define the format:** a directory named `<analysis>.sipnab/` containing:
  - `report.json` — the canonical analysis output (existing JSON schema, no changes)
  - `audio/<call_id>-<ssrc>.wav` — extracted audio from `extract_audio` operations (already produced by the existing `audio` feature)
  - `source.pcap` — optional, the original capture file (copied in if requested)
  - `manifest.json` — directory contents listing with checksums and schema version, written first so a partially-written `.sipnab` is detectable
- [ ] **CLI:** `sipnab --open <foo.sipnab>` re-creates the dialog/stream state from `report.json` and serves it via TUI / `--mcp` / `--api` exactly as if from a live capture. No re-analysis pass.
- [ ] **CLI:** `sipnab -I <foo.pcap> --save-project <foo.sipnab>` produces the project directory after analysis. Implies `--call-report` style analysis on every dialog and audio extraction on every stream.
- [ ] **Schema versioning:** `manifest.json` carries a `schema_version: 1` field; `--open` rejects unknown future versions with a clear "upgrade sipnab" message.
- [ ] **MCP tool:** add `open_project(path)` to Phase 8.3's tool surface — agent can ask sipnab to load a `.sipnab` directory and then query it normally.

**Existing release wrap-up:**
- [ ] **Demo pcap + agent prompt examples** in `demos/mcp/`:
  - `demos/mcp/one-way-audio/` — pcap exhibiting one-way audio, example agent transcript showing diagnosis via MCP tools
  - `demos/mcp/scanner-attack/` — pcap with friendly-scanner traffic, agent detection workflow
  - `demos/mcp/customer-complaint/` — pcap with a degraded call, agent root-cause analysis
- [ ] **Update `CHANGELOG.md`** for v0.4.0 with the MCP feature, quality timeline upgrade, and `.sipnab` format
- [ ] **Update `README.md`** Quick Start with an MCP example
- [ ] **Update `man/sipnab.1`** with the `--mcp*` flag set, `--open`, `--save-project`, `--rtp-interval-ms`
- [ ] **CI:**
  - Add `cargo build --features mcp --no-default-features` and `cargo build --features mcp-http --no-default-features` to `.github/workflows/`
  - Add an end-to-end test job that spawns `sipnab --mcp -I <pcap>` and runs the official `mcp-inspector` against it
  - Add a clippy job with `-D clippy::await_holding_lock` on the `mcp` feature
  - Add a round-trip test: `sipnab -I foo.pcap --save-project foo.sipnab` then `sipnab --open foo.sipnab --json` produces output identical to the direct `-I foo.pcap --json` run
- [ ] **Cross-build verification:** `cross build --release --target x86_64-unknown-linux-gnu --features full` succeeds with rmcp in the dependency graph
- [ ] **Release artifacts:** `.deb` and `.rpm` packaging (`contrib/deb/`, `contrib/rpm/`) include `sipnab-mcp.service` and `gen-mcp-token.sh`
- [ ] **Website:** add an MCP page to `website/` covering the agent debugging story; add a `.sipnab` format reference page
- [ ] **Blog post / OpenSIPS Summit follow-up:** "An AI Apprentice for SIP Debugging" — short post pointing to the demos. (Aligns with prior OpenSIPS Summit talk on AI + OpenSIPS.)

**Gate — 8.6 is done when:**
- [ ] All three demos run end-to-end and produce the expected agent output
- [ ] CI passes including the new MCP jobs
- [ ] Cross-build artifacts include the MCP feature when `--features full` is requested
- [ ] `.deb` and `.rpm` install cleanly on test VMs and `systemctl start sipnab-mcp.service` works after token file is created
- [ ] sipnab.com has a documented MCP landing section
- [ ] **★** `sipnab -I foo.pcap --rtp-interval-ms 680 --json` produces `quality_intervals` arrays whose entries are ~680ms apart with `status` fields populated
- [ ] **★** Round-trip test: `--save-project` then `--open` produces identical JSON output to direct analysis (CI gate)
- [ ] **★** Opening a `.sipnab` from another machine (different user, different filesystem layout) works without modification — paths inside the project are relative
- [ ] **★** `sipnab --open foo.sipnab --mcp` serves every advertised MCP tool over the rehydrated project — agent can `list_dialogs`, `get_dialog_report`, `rtp_stats`, `find_problems`, `tail_dialogs` against a `.sipnab` source identically to a live or pcap source. Verifies the rehydration path actually populates `DialogStore`/`StreamStore` to the level MCP requires.

**Tests — 8.6 deliverables (D24):**
- [ ] `tests/rtp/quality_interval_680ms.rs` — `--rtp-interval-ms 680` produces `quality_intervals` whose entries are 680ms ± 5ms apart with `status` field populated; trichotomy thresholds covered with positive cases for each (`ok`, `poor`, `uncertain`)
- [ ] `tests/rtp/quality_interval_legacy.rs` — `--rtp-interval` (in seconds, the existing flag) continues to work and produces the same JSON shape as before, ensuring backwards compat
- [ ] `tests/project/sipnab_format_save.rs` — `sipnab -I <pcap> --save-project <foo.sipnab>` produces the directory layout (`manifest.json` first, then `report.json`, `audio/`, optional `source.pcap`); manifest checksums match file contents
- [ ] `tests/project/sipnab_format_open.rs` — `sipnab --open <foo.sipnab> --json` produces JSON identical to direct `--I foo.pcap --json` (golden file round-trip)
- [ ] `tests/project/sipnab_cross_machine.rs` — opens a `.sipnab` directory built on a different filesystem layout (relative paths only); asserts no absolute paths leak into the manifest
- [ ] `tests/project/sipnab_schema_version.rs` — opening a `.sipnab` with `manifest.json` containing `schema_version: 999` produces a clear "upgrade sipnab" error and exits non-zero
- [ ] `tests/project/sipnab_call_id_filesystem_safe.rs` — Call-IDs containing `@`, `/`, `:` are encoded losslessly in `audio/<call_id>-<ssrc>.wav` filenames; round-trip identity preserved
- [ ] `tests/mcp/open_project_serves_tools.rs` — `sipnab --open foo.sipnab --mcp` serves every advertised MCP tool over the rehydrated state (one assertion per tool against fixture content)
- [ ] CI workflow `.github/workflows/cross-build.yml` confirms `cross build --release --target x86_64-unknown-linux-gnu --features full` succeeds with rmcp in the dep graph
- [ ] `tests/mcp/inspector_e2e_full.rs` — extended version of 8.1's smoke test covering all advertised tools (post-8.3) including `snapshot_pcap` and the new `open_project`

**Docs — 8.6 deliverables:**
- [ ] `docs/mcp-overview.md`, `docs/mcp-tools.md`, `docs/mcp-deployment.md`, `docs/mcp-agent-cookbook.md`, `docs/mcp-notifications.md`, `docs/mcp-hep-deployment.md` all complete and cross-linked
- [ ] **★** `docs/sipnab-project-format.md` — `.sipnab` directory layout, manifest schema, schema versioning policy, sharing analyses across machines
- [ ] CHANGELOG entry for v0.4.0
- [ ] Updated man page

---

### 8.7 — ★ Per-Call Asymmetry Heuristics (PRIORITY)

Six new diagnostic checks comparing the two RTP legs of a SIP call to flag asymmetries that typically indicate real network-path or signaling problems. All computable from data sipnab already tracks in `SipDialog` and `RtpStream` — no new capture work, no new parsing. Borrowed from Pcaptix's per-call heuristics list (validated as industry-standard triage signals).

**Why priority:** highest ROI in the entire roadmap. Each check is roughly half a day of code. They light up the existing diagnostic alias system (`--problems` becomes meaningfully better), feed JSON output and TUI badges automatically, and become MCP tool inputs for Phase 8.3's `find_problems` for free.

**Module placement:** `src/rtp/diagnosis.rs` already exists with `MediaDiagnosis` (which currently produces `one_way_audio`, `nat_mismatch`, `no_media`). Extend it with a new `CallAsymmetry` struct and a `diagnose_asymmetry(dialog, streams)` function that returns the six new findings. No new module.

**The six checks:**

- [ ] **Codec asymmetry** — A leg uses one codec, B leg uses another (e.g., A→B is G.711µ, B→A is G.729). Detect by comparing `RtpStream::codec` across the two streams associated with the same `SipDialog`. Tag: `codec_asymmetry: {a_codec, b_codec}`.
- [ ] **Ptime asymmetry** — A leg uses one packetization time, B leg uses another (e.g., 20ms vs 30ms). Detect by comparing inferred ptime from packet inter-arrival or from SDP `a=ptime:`. Tag: `ptime_asymmetry: {a_ptime_ms, b_ptime_ms}`.
- [ ] **Payload type asymmetry** — Different RTP payload types in each direction when the negotiated codec is the same (indicates SDP/codec-negotiation bug or middlebox rewriting). Tag: `payload_asymmetry: {a_pt, b_pt}`.
- [ ] **Duration asymmetry** — A leg's stream lasted significantly longer than B leg's (default threshold: >5% difference AND >2 seconds absolute). Indicates one side hung up or dropped media. Tag: `duration_asymmetry: {a_duration_sec, b_duration_sec, delta_sec}`.
- [ ] **Late media** — RTP for a leg started significantly *after* the 200 OK (default threshold: >500ms). Indicates far-end took too long to start sending, or RTP path wasn't ready when signaling completed. Tag: `late_media: {leg, delay_after_200_ok_ms}`.
- [ ] **One-sided silence** — One leg has substantial RTP but the audio energy is below a silence threshold (default: -50 dBFS) for >50% of the call. Existing `audio` feature can compute energy from decoded samples. Distinct from `one_way_audio` (which is "no RTP at all in one direction"). Tag: `one_sided_silence: {leg, silence_pct}`.
- [ ] **Runtime capability gate for `one_sided_silence`** — this is the only check that requires `audio` to be compiled in. When `audio` is absent, the check is skipped at runtime and the response carries `silence_unavailable: true` alongside the other five asymmetry signals. Energy computation must also be codec-aware: G.711 silence is "near-zero PCM" but Opus DTX produces no packets at all (which is `one_way_audio`, not `one_sided_silence`), and comfort noise (CN payload type 13) should be classified as silence not signal. The codec-awareness logic is the bulk of the implementation cost — budget 1.5–2 days for this check alone (vs. ~half a day for each of the other five).

**Wiring:**
- [ ] Add `CallAsymmetry` to `MediaDiagnosis` (extend the struct) so existing JSON output picks it up via the `diagnosis` field — backwards compatible additive change.
- [ ] Add the six new diagnostic aliases in `src/sip/dsl.rs::expand_alias`: `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`, `silent-leg`. Each expands to the corresponding DSL expression so `--filter codec-asym` works at the CLI.
- [ ] Update the `--problems` alias to include the new checks in the OR'd union (preserves backwards compatibility — `--problems` still flags everything, just more thoroughly now).
- [ ] **TUI: add a new `Flags` column to `src/tui/call_list.rs` for asymmetry badges.** No badge column exists today — `SortColumn` enum at `:28` lists ten columns: `Index, Method, From, To, Source, Destination, State, Messages, Date, Pdd`. Adding a new column requires:
  - New `SortColumn::Flags` variant + entry in `ALL_COLUMNS` (`:52`)
  - Width allocation in `compute_column_widths` (`:589`) — fixed 6-character width
  - Visibility integration with `apply_visible_columns` (`:270`) and `toggle_column_visibility` (`:244`)
  - Theme palette additions for the per-glyph colors (one color per asymmetry kind for at-a-glance scanning)
  - Sort comparator (sort by count of set flags, descending) so users can sort to see "most-broken calls first"
  - Glyphs: `C=codec, P=ptime, Y=payload, D=duration, L=late, S=silent`. Unset flags render as a dim placeholder (e.g., `·`) so column width never shifts as the dialog list updates.
- [ ] **Alternative considered (and rejected):** embedding glyphs into the existing `State` column. Rejected because `State` is sort-cycled and width-tuned for the state strings (`Trying`, `InCall`, `Completed`, etc.) and adding glyphs would either truncate state names or balloon the column.
- [ ] MCP: Phase 8.3's `find_problems` tool accepts the new alias names in its `kinds` parameter; no other code change needed because the wiring goes through `expand_alias` already.

**Threshold configuration:**
- [ ] All thresholds configurable via TOML `[limits.asymmetry]` section: `duration_pct_delta` (default 5), `duration_min_delta_sec` (default 2.0), `late_media_threshold_ms` (default 500), `silence_dbfs_threshold` (default -50), `silence_pct_threshold` (default 50).
- [ ] Sensible defaults are in `src/config.rs::Limits`, no CLI flags added (would be flag bloat for tunables that 99% of users won't touch).

**Gate — 8.7 is done when:**
- [ ] All six checks have unit tests with a hand-crafted dialog + streams that exhibit each asymmetry, plus a negative case
- [ ] Test pcaps in `tests/pcap-samples/` exercise each of the six (sourced from real captures or synthesized; some likely already exist for `one-way` and could be adapted)
- [ ] `--filter codec-asym` against a test pcap returns exactly the expected dialogs
- [ ] JSON output: `diagnosis.codec_asymmetry`, `.ptime_asymmetry`, `.payload_asymmetry`, `.duration_asymmetry`, `.late_media`, `.one_sided_silence` are present (or null for "not detected") on every dialog
- [ ] TUI: the badges render correctly without disrupting existing column widths
- [ ] MCP `find_problems` with `kinds: ["codec-asym"]` returns only dialogs with codec asymmetry; with `kinds: ["problems"]` returns the full union including the new checks
- [ ] `--problems` CLI alias picks up the new checks (regression test against the existing `--problems` test suite)
- [ ] Performance: regression on the existing `parser_bench` benchmark < 2% (the asymmetry checks are O(streams_per_dialog), trivial overhead per dialog)

**Tests — 8.7 deliverables (D24):**
- [ ] `tests/rtp/asymmetry_codec.rs` — hand-crafted dialog with G.711µ on A leg and G.729 on B leg; positive case asserts `codec_asymmetry: {a_codec, b_codec}` is set; negative case (matching codecs) asserts the field is `null`
- [ ] `tests/rtp/asymmetry_ptime.rs` — 20ms vs 30ms ptime fixture; positive + negative; SDP-derived ptime and RTP-inter-arrival-derived ptime both covered
- [ ] `tests/rtp/asymmetry_payload_type.rs` — same negotiated codec, different PTs in each direction; positive + negative
- [ ] `tests/rtp/asymmetry_duration.rs` — A leg 30s, B leg 25s (above 5% threshold + 2s absolute) is flagged; A leg 30s, B leg 29.5s is not flagged
- [ ] `tests/rtp/asymmetry_late_media.rs` — RTP starts 600ms after 200 OK is flagged with the new threshold; 400ms is not
- [ ] `tests/rtp/asymmetry_silence.rs` — fixture with `audio` feature on: low-energy decoded PCM for >50% of call is flagged as `one_sided_silence`; baseline-noise stream is not. Codec-aware: Opus DTX produces `one_way_audio` (not silence); G.711 with comfort-noise PT 13 is classified silence not signal
- [ ] `tests/rtp/asymmetry_silence_no_audio_feature.rs` — same fixture compiled with `--no-default-features --features mcp`; response carries `silence_unavailable: true` and the other five asymmetry signals are present and correct (capability check works)
- [ ] `tests/dsl/asymmetry_aliases.rs` — each of the six new aliases (`codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`, `silent-leg`) returns the expected dialogs from a multi-fixture corpus
- [ ] `tests/dsl/problems_alias_regression.rs` — existing `--problems` test corpus (from before 8.7) continues to pass; new asymmetry conditions are picked up additively (no false-negative regression)
- [ ] `tests/tui/flags_column.rs` — call list flag column renders without disrupting existing column widths; sort by flag count works; theme palette covers all six glyphs
- [ ] `tests/mcp/find_problems_asymmetry.rs` — `find_problems` with `kinds: ["codec-asym"]` returns only codec-asymmetric dialogs; `kinds: ["problems"]` returns the full union including all six new checks
- [ ] `benches/asymmetry_overhead.rs` — `criterion` bench: parser_bench regression with 8.7 active is < 2% (gate criterion encoded as test)

**Docs — 8.7 deliverables:**
- [ ] `docs/diagnostic-aliases.md` — extend with the six new aliases, threshold meanings, when each is triggered, common root causes (e.g., codec asymmetry usually means a transcoding B2BUA on the path)
- [ ] Update `docs/filter-dsl.md` with the new field names (`codec_asymmetry`, `ptime_asymmetry`, etc.) for direct DSL use
- [ ] Update `docs/mcp-tools.md` `find_problems` entry to list the new `kinds` values
- [ ] Add an `examples/diagnostic-recipes.md` cookbook entry: "diagnose a customer complaint about choppy audio" → walkthrough using the new checks plus existing RTP quality data

---

---

## Phase 9 — REST API Self-Description & Observability

**Goal:** Make the REST API self-describing for SDK generation and instrument the entire pipeline with OpenTelemetry so sipnab is observable in a standard Tempo/Prometheus/Loki stack.
**Milestone (9.1):** `openapi-generator` produces a working Python client from sipnab's published `openapi.json` that calls `/v1/dialogs/:call_id` and parses the response into typed objects without manual schema writing.
**Milestone (9.2):** A SIP INVITE captured by sipnab produces a Tempo trace with spans for capture → parse → dialog state transition → API/MCP handler return, with `call_id` as a span attribute searchable from Grafana.
**Release target:** v0.5.0.

**Exit criteria — Phase 9 is done when:**
- [ ] `cargo build --features openapi --no-default-features` produces a binary that serves `openapi.json` and Swagger UI on the existing axum stack
- [ ] CI generates Python and TypeScript clients from `openapi.json` and runs a smoke test compile on each
- [ ] Breaking changes to API request/response shapes are caught in CI by `openapi-diff`
- [ ] `cargo build --features otel` produces a binary that exports OTLP traces to a configurable endpoint
- [ ] Live capture on a test pcap with OTel enabled produces traces visible in Jaeger / Tempo with the expected span hierarchy
- [ ] OpenTelemetry instrumentation adds < 5% overhead to capture throughput at 10K packets/sec (measured via `criterion` benchmark with and without `otel` feature)
- [ ] `traceparent` header propagation: when an incoming SIP message carries a `Trace-Parent` header (RFC-compliant W3C trace context), the resulting sipnab span is linked to the upstream trace
- [ ] Prometheus `/metrics` endpoint (already in v6 Phase 5) exposes new sipnab-internal metrics: `dialogs_total`, `parse_errors_total`, `dropped_events_total`, `mcp_tool_calls_total{tool}`, `api_requests_total{endpoint,status}`

---

### 9.1 — OpenAPI Spec & SDK Generation

The current REST API (Phase 6) is documented only in markdown. SDK consumers are forced to hand-write request/response types, which silently breaks when the server changes. OpenAPI fixes both.

- [ ] **Add dependencies (feature-gated under `openapi`):**
  ```toml
  utoipa = { version = "5", features = ["axum_extras", "chrono", "uuid"], optional = true }
  utoipa-swagger-ui = { version = "8", features = ["axum"], optional = true }

  # Add features:
  openapi = ["api", "dep:utoipa", "dep:utoipa-swagger-ui"]
  ```
  `openapi` builds on `api` since the spec describes the existing REST surface.
- [ ] **Annotate every axum handler in `src/output/api.rs` with `#[utoipa::path(...)]`:**
  - HTTP method, path, request parameters, response types, status codes
  - One annotation per handler (`list_dialogs`, `get_dialog`, `get_dialog_report`, `list_streams`, `get_stream`, `get_stats`, `health_check`, `get_metrics`)
  - Group with OpenAPI tags: `dialogs`, `streams`, `stats`, `health`, `metrics`
- [ ] **Derive `ToSchema` on every JSON struct in `src/output/json.rs` and `src/output/api.rs`:**
  - `DialogJson`, `StreamJson`, `MessageJson`, `TimingJson`, `SdpExchangeJson`, `DiagnosisJson`, `QualityIntervalJson`, `DialogListParams`, `StreamListParams`
  - Document each field with `///` comments — utoipa lifts these into the spec descriptions
- [ ] **Build the `OpenApi` aggregator struct:**
  ```rust
  #[derive(utoipa::OpenApi)]
  #[openapi(
      paths(list_dialogs, get_dialog, get_dialog_report, list_streams, get_stream, get_stats, health_check),
      components(schemas(DialogJson, StreamJson, /* ... */)),
      tags((name = "dialogs", description = "..."), /* ... */),
      info(title = "sipnab REST API", version = env!("CARGO_PKG_VERSION"))
  )]
  struct ApiDoc;
  ```
- [ ] **Mount Swagger UI at `/docs`** and serve `openapi.json` at `/openapi.json` on the existing axum Router. Reuse the existing bearer-token auth (skip auth on `/docs` and `/openapi.json` only when an explicit `--openapi-public` flag is set; default to requiring auth even for the docs).
- [ ] **Generate `openapi.json` at build time** via a `build.rs` extension or a `cargo xtask openapi` command. Output to `target/openapi.json` and publish as a GitHub Releases asset.
- [ ] **Add CI client-generation jobs:**
  - Python: `openapi-generator-cli generate -i openapi.json -g python -o gen/python && cd gen/python && pip install . && python -c "import sipnab_client"`
  - TypeScript: `openapi-generator-cli generate -i openapi.json -g typescript-axios -o gen/ts && cd gen/ts && npm install && npm run build`
- [ ] **Backwards-compat checking:** `openapi-diff` job in CI compares `openapi.json` against the spec from the last release tag; fail PR if breaking changes are present without a `breaking-change` label.
- [ ] **MCP coexistence:** Phase 8's MCP tool descriptions remain the source of truth for MCP. OpenAPI describes only the REST surface. The two are independent — an agent uses MCP, a web dashboard uses the REST OpenAPI client. Document this division clearly.
- [ ] **Versioning policy:** OpenAPI spec version follows `CARGO_PKG_VERSION`. The existing `schema_version: 1` field on every JSON response is preserved; OpenAPI documents it.

**Gate — 9.1 is done when:**
- [ ] `curl http://127.0.0.1:8080/openapi.json` returns a valid OpenAPI 3.1 spec covering every endpoint
- [ ] `curl http://127.0.0.1:8080/docs` returns a working Swagger UI page
- [ ] Spec validates with `openapi-spec-validator` and `redocly lint`
- [ ] CI Python client generation produces a package that imports cleanly and can call `/v1/dialogs` against a running sipnab in CI
- [ ] CI TypeScript client generation produces a package that builds with `tsc` strict mode
- [ ] `openapi-diff` correctly detects a deliberately introduced breaking change (renaming a required field) and fails CI
- [ ] Field documentation lifted from `///` comments appears in Swagger UI for `DialogJson` and at least three other schemas

**Tests — 9.1 deliverables (D24):**
- [ ] `tests/openapi/spec_validity.rs` — generated `openapi.json` validates with `openapi-spec-validator` (invoked from build.rs or a dedicated CI step) and `redocly lint`
- [ ] `tests/openapi/swagger_ui_smoke.rs` — `GET /docs` returns a Swagger UI page; `GET /openapi.json` returns valid JSON; both return 401 without bearer token unless `--openapi-public` is set
- [ ] `tests/openapi/breaking_change_detection.rs` (CI workflow + golden file) — `openapi-diff` detects a deliberately-introduced breaking change (rename a required field) and fails the PR; allowed by adding the `breaking-change` label
- [ ] `.github/workflows/openapi-clients.yml` — generates Python and TypeScript clients via `openapi-generator-cli`, builds each, runs a smoke test that calls `/v1/dialogs` against a CI-spawned sipnab
- [ ] `tests/openapi/field_doc_propagation.rs` — asserts at least three schemas (`DialogJson`, `StreamJson`, `MessageJson`) have non-empty descriptions in the generated spec, lifted from `///` comments
- [ ] `tests/openapi/version_pinning.rs` — generated spec's `info.version` matches `CARGO_PKG_VERSION`; `schema_version: 1` is preserved on every JSON response

**Docs — 9.1 deliverables:**
- [ ] `docs/openapi.md` — how to use the published spec, client generation examples for Python, TypeScript, Go, Rust
- [ ] `docs/sdk-stability.md` — versioning policy, schema_version semantics, deprecation timeline
- [ ] Update `docs/api-reference.md` to point to Swagger UI and `openapi.json` as the canonical source
- [ ] GitHub release notes template includes "OpenAPI spec changes" section

---

### 9.2 — OpenTelemetry Tracing & Metrics

sipnab is currently observable via `log` macros and the existing Prometheus endpoint. For correlated tracing across a typical SIP infrastructure stack (OpenSIPS, Asterisk, application platforms, sipnab) — alongside the OpenTelemetry module shipped in OpenSIPS in early 2026 — sipnab needs to participate in the same trace context.

**Deployment model (per D20):** OTel follows the Infrastructure-Optional Integration rule — `otel` Cargo feature controls compile-time inclusion; `--otel-endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT` env) controls runtime activation. Without an endpoint configured, no OTLP exporter is constructed, no outbound connections are attempted, and sipnab logs nothing about OTel. Operators run their own Tempo/Jaeger/Grafana — sipnab does not embed or recommend a specific collector deployment.

The "read" half of OTel does not apply: sipnab exports traces and metrics, it does not consume them. The one exception is W3C `traceparent` header parsing on incoming SIP messages — that's just header extraction, not a connection to anything.

- [ ] **Add dependencies (feature-gated under `otel`):**
  ```toml
  tracing = "0.1"
  tracing-subscriber = { version = "0.3", features = ["env-filter", "json"], optional = true }
  tracing-opentelemetry = { version = "0.27", optional = true }
  opentelemetry = { version = "0.27", optional = true }
  opentelemetry_sdk = { version = "0.27", features = ["rt-tokio"], optional = true }
  opentelemetry-otlp = { version = "0.27", default-features = false, features = ["http-proto", "reqwest-blocking-client", "trace", "metrics"], optional = true }
  opentelemetry-semantic-conventions = { version = "0.27", optional = true }

  # Add features:
  otel      = ["native", "dep:tokio", "dep:tracing-subscriber", "dep:tracing-opentelemetry",
               "dep:opentelemetry", "dep:opentelemetry_sdk", "dep:opentelemetry-otlp",
               "dep:opentelemetry-semantic-conventions"]
  otel-grpc = ["otel", "opentelemetry-otlp/grpc-tonic"]
  ```
  **OTLP transport choice:** the default exporter is OTLP over **HTTP/protobuf** (`http-proto`), not gRPC. This is a deliberate split from the rest of the plan's "no gRPC" rule — the OTLP exporter is outbound-only (sipnab is the client to the operator's collector), so the gRPC dep tree adds complexity without adding capability for the common case. Operators who specifically need gRPC OTLP (some Tempo/OTel-Collector deployments enforce gRPC ingest) opt in via `--features otel-grpc`, which adds tonic+prost on demand.
  **Tokio runtime origin:** `otel` declares `dep:tokio` directly. When `api`/`mcp-http` is also enabled, sipnab reuses their tokio runtime; when neither is, `otel` constructs its own current-thread runtime (mirroring `start_api_server`'s pattern) so the exporter has somewhere to run in stdio/CLI mode.
  Note: `tracing` itself is unconditional (lightweight, always-compiled facade); only the OTel exporter and subscriber are feature-gated. The mechanical `log::*` → `tracing::*` migration is performed in Phase 8.0 — by the time 9.2 starts, the codebase is already tracing-native and 9.2 only adds spans, attributes, and the OTLP exporter wiring.
- [ ] **Add CLI flags (gated under `otel` feature):**
  - `--otel-endpoint <URL>` — OTLP collector endpoint (default: respects `OTEL_EXPORTER_OTLP_ENDPOINT` env)
  - `--otel-service-name <NAME>` — service name for traces (default: `sipnab`)
  - `--otel-sampling-ratio <0.0–1.0>` — head-based sampling (default: 0.01 = 1%)
  - `--otel-resource <KEY=VALUE>` — repeatable resource attributes
- [ ] **Instrument the right granularity, not the hot path** — there is no `capture::parse::parse_packet` to wrap. The parse fan-out is split across `tui_process_packet` (`main.rs:870`), `mirror_to_shared_stores` (`:2142`), and `processor.process_packet` from the batch loop, each calling `sip::is_sip_message` / `sip::parse_sip` / `parse_rtp_header`. Per-packet spans on a 10K pkt/s capture would breach the 5% perf gate even at TRACE-filtered levels. Instrument at these levels only:
  - **Capture session (root span):** `capture::start_capture` and `capture::start_multi_capture` — one span per session, lives for the duration of the run
  - **Dialog state transitions:** `sip::dialog_store::DialogStore::process_message` (`:99`) (attributes: `call_id`, `method`, `state_before`, `state_after`) — one span per message; this is already medium-frequency, not hot-path
  - **HTTP/MCP request boundary:** every axum handler in `output::api` (attributes from OTel HTTP semantic conventions, plus `endpoint`); every `#[tool]` method in `src/mcp/server.rs` (attributes: `tool_name`, `success`, `error_code`)
- [ ] **Use `tracing::event!`, not spans, for parse errors:**
  - `sip::parse_sip` returning `Err` emits a TRACE event with the failure kind — no span construction on the per-packet hot path
  - `parse_rtp_header` failures: same pattern
  - Aggregate counts via the existing Prometheus counters; OTel sees only the events
- [ ] **Span attributes — semantic conventions:**
  - Use OpenTelemetry HTTP semantic conventions for axum/MCP handlers
  - Custom attributes: `sipnab.call_id`, `sipnab.dialog_state`, `sipnab.rtp.ssrc`, `sipnab.rtp.codec`, `sipnab.mcp.tool`
  - Never include SIP body content or SRTP key material in span attributes (D19)
- [ ] **`traceparent` header propagation (incoming):**
  - When SIP messages carry a `Trace-Parent` or `traceparent` header (W3C Trace Context), extract the trace ID and parent span ID and link the resulting sipnab span to that upstream trace
  - Especially important for traces flowing from OpenSIPS → sipnab via observed SIP traffic
- [ ] **Metrics via OTel:**
  - Counter `sipnab_dialogs_total{state}` — dialog count by terminal state
  - Counter `sipnab_parse_errors_total{kind}` — parser failures by failure kind
  - Counter `sipnab_dropped_events_total{sink}` — broadcast capacity drops, per sink
  - Counter `sipnab_mcp_tool_calls_total{tool,outcome}` — MCP tool invocations
  - Histogram `sipnab_api_request_duration_seconds{endpoint}` — REST API latency
  - Histogram `sipnab_dialog_pdd_milliseconds` — PDD distribution (already computed; just expose)
  - Gauge `sipnab_active_dialogs` — current dialog count
  - Gauge `sipnab_active_streams` — current stream count
- [ ] **Metrics export:** OTLP for the otel-pull world; the existing `--metrics` Prometheus endpoint stays (Phase 5) and gains the new metrics via the `tracing-prometheus` bridge.
- [ ] **Sampling discipline (gotcha for the parse hot path):**
  - Default 1% head sampling means 99% of `parse_packet` spans never reach the exporter, but they're still constructed in memory
  - Use `tracing::span!(Level::TRACE, ...)` for high-volume paths and configure the subscriber's `EnvFilter` to reject `TRACE` by default — spans below the filter level are zero-cost
  - Document the recommended `RUST_LOG`/`OTEL_*` configuration for production vs. debugging
- [ ] **Performance gate:** `criterion` benchmark added that compares per-packet processing throughput with and without `otel` feature. With `otel` compiled in but no exporter active: regression > 2% fails CI (tightened from 5% — without per-packet spans this is achievable). With exporter active and 1% sampling: regression > 5% fails CI.

**Gate — 9.2 is done when:**
- [ ] `sipnab --otel-endpoint http://localhost:4317 -d eth0` exports OTLP traces to a local Tempo or Jaeger, visible within 30 seconds
- [ ] A test SIP INVITE flow produces a span tree: `capture` → `parse_packet` → `process_message` → `dialog_state_change`, with `call_id` searchable
- [ ] An MCP tool call produces a span linked to its parent (the MCP request span)
- [ ] When the test SIP INVITE carries a synthetic `Trace-Parent` header, the resulting sipnab span shows up under the upstream trace in Tempo
- [ ] Prometheus scrape of `/metrics` returns all new metric families with non-zero values after a 1-minute capture
- [ ] Benchmark: `parse_packet` throughput regression with `otel` feature enabled is ≤ 5%
- [ ] No SIP body or key material appears in any exported span attribute (verified by tcpdump on the OTLP socket against a `--tls-key` capture)
- [ ] Default sampling (1%) on a 10K-packet/sec capture does not OOM the OTel exporter buffer

**Tests — 9.2 deliverables (D24):**
- [ ] `tests/otel/exporter_smoke.rs` — `--otel-endpoint http://localhost:4317` exports OTLP traces to a local Tempo (CI-spawned via docker-compose); a synthetic INVITE flow produces the expected span tree (capture session → process_message → MCP/API handler) within 30s
- [ ] `tests/otel/traceparent_extraction.rs` — synthetic SIP message carrying `Trace-Parent` header produces a sipnab span linked to the upstream trace ID; missing header produces a span with no parent (root)
- [ ] `tests/otel/no_secret_leak.rs` — capture-with-`--tls-key` running with otel exporter on; OTLP socket is observed (via tcpdump in CI or a captured-bytes assertion); no SIP body bytes, no SRTP key bytes appear in any span attribute (D19 enforcement)
- [ ] `tests/otel/sampling_buffer_safety.rs` — 10K-packet/sec capture with default 1% sampling does not OOM the OTel exporter buffer over a 5-minute soak (CI-friendly variant: assert RSS stays under a calibrated bound)
- [ ] `benches/parse_with_otel.rs` — `criterion` bench: per-packet processing throughput regression with `otel` compiled but no exporter active is ≤ 2%; with exporter active and 1% sampling is ≤ 5%. Both numbers are gates encoded as test assertions, not eyeballed.
- [ ] `tests/metrics/sipnab_metrics_present.rs` — Prometheus scrape after a 1-minute capture returns all eight new metric families (`dialogs_total`, `parse_errors_total`, etc.) with non-zero values
- [ ] `tests/otel/span_attribute_schema.rs` — every span attribute name is in the documented schema (`sipnab.call_id`, `sipnab.dialog_state`, etc. + standard OTel HTTP semconv); fails CI if a new attribute name is introduced without doc entry

**Docs — 9.2 deliverables:**
- [ ] `docs/observability.md` — full OTel guide: endpoint config, sampling, metric reference, span attribute reference
- [ ] `docs/grafana-setup.md` — example Tempo + Prometheus + Loki dashboard JSON for sipnab
- [ ] `contrib/grafana/sipnab-dashboard.json` — extend the existing dashboard with sipnab-internal metrics from Phase 9.2 (parse_errors, dropped_events, mcp_tool_calls, api_request_duration, dialog_pdd histogram, active_dialogs/streams gauges)
- [ ] `contrib/otel-collector.yaml` — example OTel Collector config that sipnab traces flow through
- [ ] Update `docs/cli-reference.md` with the `--otel-*` flags
- [ ] Update `docs/security-model.md` with OTel-specific notes (no key material in spans, sampling implications for sensitive captures)

---

## Phase 10 — NATS Event Bus (Deferred to Future Considerations)

**Status:** Deferred. The plan previously listed Phase 10 as "Conditional" with concrete tickets, contrib files, and gate criteria *and* a trigger condition that may never fire (NATS already part of the operator's infrastructure AND a non-MCP/WS/SSE consumer of sipnab events exists). Carrying detailed planning for a phase whose trigger may never fire is overhead. WebSocket and SSE from Phase 8.4b cover the "external systems consume sipnab events" case for the vast majority of deployments without any external dependency.

The design notes — subject hierarchy, NDJSON envelope, NATS message headers, JetStream replay model, `traceparent` correlation — are preserved in the **Future Considerations** section below as "NATS sink (deferred)". When a deployment site asks for it, the design is ready to pick up; until then, no calendar effort is allocated.

**Decision rule for un-deferring:** all three are true. (1) An operator with NATS in production asks for sipnab→NATS. (2) Their need is *not* served by WebSocket/SSE (e.g., they need JetStream replay, or they want fan-out to >100 subscribers per server). (3) The 8.4a substrate is in production and stable. At that point, the NATS sink is ~2–3 days of work given the substrate already exists.

---

## Phase 11 — Statistical Analysis & Perceptual MOS

**Goal:** Add two analyses that commercial tools (Pcaptix, Sevana AQuA) ship and that sipnab currently lacks: cross-stream feature regression and perceptual MOS scoring of decoded audio.
**Milestone (11.1):** `sipnab -I large_corpus.pcap --stats-analyze --target=mos --json` returns a feature-importance ranking ("loss_ratio explains 73% of MOS variance, jitter_max is second") that an operator can use to identify the dominant cause of quality issues across a fleet.
**Milestone (11.2):** `sipnab -I foo.pcap --features perceptual_mos --json` produces both `network_mos` (existing E-model) and `perceptual_mos` (NISQA score) for every stream, with the two values diverging on streams where the network looks fine but the audio sounds bad (transcoding artifacts, codec mismatch, DTX bugs).
**Release target:** v0.6.0.

**★ Design priority, build-when-ready:** the **design** for 11.1 and 11.2 should be written *before* Phase 8 ships (so it informs Phase 8 architectural choices). The **build** is deferred until after Phase 8 ships — sequence Phase 11 against whatever has emerged by then, rather than committing now.

**Exit criteria — Phase 11 is done when:**
- [ ] `--stats-analyze` produces feature importance rankings on a corpus of 100+ calls, output as JSON with the same schema versioning as the rest of sipnab
- [ ] Perceptual MOS regression test: 20-pcap corpus with known good and known bad audio; NISQA scores correlate with subjective ratings within reasonable bounds (validated against published NISQA paper benchmarks)
- [ ] `network_mos` vs `perceptual_mos` divergence flagged automatically when `|delta| > 0.5` — surfaces in the existing diagnosis system as a new tag (`mos_divergence`)
- [ ] No NISQA model file is bundled in the default binary (added cost is opt-in)
- [ ] Cross-build (musl, ARM64) still works with the perceptual_mos feature compiled in

---

### 11.1 — Cross-Stream Statistical Analysis

Treat the capture as a dataset and ask which network features predict perceived (or measured) quality. Borrowed from Pcaptix's Statistics tab. Twelve features per call: RTP packet count, lost packets, loss ratio, illegal packets, RTCP packets, jitter avg/max/min, delay avg/max, duration, plus the alternative MOS as a feature.

- [ ] **Add dependencies (feature-gated under `stats`):**
  ```toml
  linfa = { version = "0.7", default-features = false, optional = true }
  linfa-linear = { version = "0.7", optional = true }
  ndarray = { version = "0.16", optional = true }

  # Add features:
  stats = ["native", "dep:linfa", "dep:linfa-linear", "dep:ndarray"]
  ```
  `linfa` is the Rust scikit-learn analog. Only linear regression and feature importance are needed; do not pull in the full ML stack.
- [ ] **Module:** new `src/analysis/stats.rs` (and `src/analysis/mod.rs`). Functions:
  - `extract_features(dialogs: &[SipDialog], streams: &[RtpStream]) -> Vec<FeatureVector>`
  - `regress(features: &[FeatureVector], target: TargetMetric) -> RegressionResult`
  - `feature_importance(result: &RegressionResult) -> Vec<(FeatureName, f64)>`
- [ ] **Filtering policy:**
  - Streams with fewer than 10 packets: dropped (matches Pcaptix)
  - Streams with no value for the target metric: dropped
  - Zero-variance features: dropped from the regression (would crash linear regression)
  - Document these in the output JSON so the user knows what was excluded
- [ ] **CLI:** `sipnab -I <pcap> --stats-analyze --target <network_mos|perceptual_mos|loss_ratio> [--min-packets <N>] [--partition-by-subnet <CIDR>]`
- [ ] **Output:** structured JSON with feature ranking, R² score, dropped-stream count, partition breakdown if `--partition-by-subnet` was used. Pretty-printed text version for terminal users via `--text` flag.
- [ ] **MCP tool:** `analyze_features(target, min_packets?, partition_by?)` — feeds the same code path. Returns the JSON shape.
- [ ] **Subnet partitioning:** optional `--partition-by-subnet /24` (default off) groups streams by source-IP /24 (or /N for v6) and runs the regression per partition. Useful for "which edge sites are causing the badness?" Matches Pcaptix's Preferences > Analysis subnet-partition feature.

**Gate — 11.1 is done when:**
- [ ] On a corpus of 100 streams with synthetic loss patterns, `--stats-analyze --target network_mos` correctly identifies `loss_ratio` as the dominant predictor
- [ ] Feature dropping (zero variance, insufficient samples) is reported in the JSON and does not crash
- [ ] `--partition-by-subnet /24` with two distinct source subnets produces two separate regression results
- [ ] MCP `analyze_features` tool returns the same data as the CLI
- [ ] Stats analysis runs in < 5 seconds for a 10K-stream corpus on the M1 reference machine
- [ ] Without the `stats` feature, the binary does not contain linfa or ndarray (verified by `cargo tree --features ""`)

**Tests — 11.1 deliverables (D24):**
- [ ] `tests/analysis/feature_extraction.rs` — extracts the documented 12 features from a fixture corpus; asserts each feature has the expected value within `f64` tolerance
- [ ] `tests/analysis/regression_synthetic.rs` — corpus of 100 streams with synthetic loss patterns; `--stats-analyze --target network_mos` correctly identifies `loss_ratio` as the dominant predictor (R² > 0.7); fails CI if the inverse correlation is reported (catches sign-flip bugs)
- [ ] `tests/analysis/dropping_diagnostics.rs` — corpus mixing zero-variance features and short streams; output JSON reports the dropped counts and reasons; the regression itself does not crash
- [ ] `tests/analysis/subnet_partition.rs` — two distinct source /24 subnets in fixture; `--partition-by-subnet /24` produces two separate `RegressionResult` entries with the expected feature-importance differences between them
- [ ] `tests/mcp/analyze_features.rs` — MCP `analyze_features` tool returns identical JSON shape to the CLI `--stats-analyze --json` (golden file)
- [ ] `benches/stats_analyze.rs` — 10K-stream corpus runs in < 5s on the CI runner (gate criterion as test)
- [ ] `tests/analysis/no_linfa_in_default.rs` — `cargo tree` on default features does not include `linfa` or `ndarray` (D20 enforcement)

**Docs — 11.1 deliverables:**
- [ ] `docs/statistical-analysis.md` — feature list with definitions, regression methodology, interpretation guide, subnet partitioning use cases
- [ ] Update `docs/mcp-tools.md` with the `analyze_features` tool entry
- [ ] Example workflow in `examples/stats-recipes.md`: "find the network feature most correlated with bad calls in last week's capture corpus"

---

### 11.2 — Perceptual MOS via NISQA

Add a perceptual quality score derived from decoded audio, complementary to the existing E-model network MOS. Sevana AQuA and Pcaptix's Sevana MOS occupy this space commercially; NISQA is the credible open-source alternative.

**Why NISQA, not ViSQOL or PESQ:**
- **NISQA** (Mittag et al., 2021, MIT licensed) is a deep-learning model trained for the *non-intrusive* case — it scores quality from the degraded signal alone, no clean reference required. This matches sipnab's reality: a pcap analyzer never has the clean reference signal.
- **ViSQOL** (Google, Apache 2.0) is *intrusive* by default — needs the reference signal — and its no-reference mode is less validated. Wrong tool for this job.
- **PESQ** (ITU-T P.862) is licensed and expensive. **POLQA** (P.863) is more so. Both are intrusive. Reject for both license and intrusivity reasons.

**Implementation path:**
- [ ] **Add dependencies (feature-gated under `perceptual_mos`):**
  ```toml
  ort = { version = "2", optional = true, features = ["download-binaries"] }  # ONNX Runtime
  ndarray = { version = "0.16", optional = true }

  # Add features:
  perceptual_mos = ["native", "audio", "dep:ort", "dep:ndarray"]
  ```
  Requires `audio` (sipnab must already be decoding RTP to PCM samples).
- [ ] **NISQA model:** ONNX-converted NISQA model (~50MB). Download path:
  - Default: model is **not** bundled in the binary or default install
  - Operator runs `sipnab --download-nisqa-model` once to fetch and verify checksum into `~/.local/share/sipnab/nisqa.onnx`
  - Or operator provides `--nisqa-model <path>` pointing at their own copy
  - First use without a model present: clear error message with the download instructions
- [ ] **Module:** new `src/rtp/perceptual_mos.rs`. Function `compute_nisqa(samples: &[i16], sample_rate: u32) -> Result<f64, NisqaError>`. Internally: resample to 48kHz if needed, normalize, run through ONNX inference.
- [ ] **Per-stream computation:** `RtpStream` gains an optional `perceptual_mos: Option<f64>` field. Computed lazily (only when stream has decoded samples and `perceptual_mos` feature is active and model is available).
- [ ] **CLI:** no new flag — perceptual MOS is computed automatically when the feature is built and a model is present. `--no-perceptual-mos` flag opts out for performance-sensitive runs.
- [ ] **Divergence detection:** when `|network_mos - perceptual_mos| > 0.5`, set a new diagnosis tag `mos_divergence: {network, perceptual, delta, likely_cause}`. The `likely_cause` is heuristic:
  - Network MOS high, perceptual MOS low → "transcoding or codec issue"
  - Network MOS low, perceptual MOS high → "network impairment masked by codec resilience" (e.g., Opus PLC compensating for loss)
- [ ] **JSON output:** add `perceptual_mos` field to existing `StreamJson` (additive, `null` when not computed). Add `mos_divergence` to `MediaDiagnosis`.
- [ ] **MCP/REST:** existing `rtp_stats` tool returns `perceptual_mos` automatically when present. No new tool needed.

**Performance:**
- [ ] NISQA inference on a 10-second stream takes ~200ms on the M1 (CPU). For a 1000-stream pcap, that's 3+ minutes added — **opt-in by default** for performance reasons; document this in the help text.
- [ ] Add `--perceptual-mos-sample-pct <N>` (default 100) to score only N% of streams when running across large corpora.

**Gate — 11.2 is done when:**
- [ ] NISQA model loads and produces scores in the expected range [1.0, 5.0] for synthetic test signals
- [ ] On a 20-pcap corpus with known good/bad audio, perceptual_mos correlates with subjective ratings (Spearman ρ > 0.7)
- [ ] On a stream with low loss/jitter but heavy transcoding, `perceptual_mos < network_mos - 0.5` and `mos_divergence` is set
- [ ] Without the `perceptual_mos` feature, the binary does not contain ort or ndarray
- [ ] With the feature compiled in but no model file present, a clear error message points at `--download-nisqa-model`
- [ ] Cross-build with `--features perceptual_mos` succeeds for x86_64-musl and aarch64-gnu (ONNX Runtime supports both)
- [ ] First-use download: `sipnab --download-nisqa-model` fetches the model, verifies SHA256, writes to the standard XDG location, succeeds on Linux and macOS
- [ ] License audit: NISQA's MIT license is compatible; ONNX Runtime's MIT license is compatible

**Tests — 11.2 deliverables (D24):**
- [ ] `tests/perceptual_mos/synthetic_signals.rs` — known-good and known-bad synthetic signals (white-noise floor, clipped sine, clean tone) produce NISQA scores in the documented [1.0, 5.0] range with the expected ordering
- [ ] `tests/perceptual_mos/corpus_validation.rs` — 20-pcap corpus committed under `tests/corpora/perceptual_mos/` with subjective-rating ground truth in `tests/corpora/perceptual_mos/ratings.json`; Spearman ρ between NISQA scores and subjective ratings is > 0.7 (the gate criterion is the test)
- [ ] `tests/perceptual_mos/divergence_detection.rs` — fixture stream with low loss/jitter but heavy transcoding produces `mos_divergence` set with `likely_cause: "transcoding or codec issue"`; complementary fixture (Opus PLC over heavy loss) produces the inverse cause
- [ ] `tests/perceptual_mos/no_ort_in_default.rs` — without `perceptual_mos` feature, `cargo tree` does not include `ort` or `ndarray`
- [ ] `tests/perceptual_mos/missing_model_error.rs` — feature compiled in, no model file present, first call returns a structured error referencing `--download-nisqa-model` and exits cleanly (no panic)
- [ ] `tests/perceptual_mos/model_download.rs` (CI shell job) — `sipnab --download-nisqa-model` fetches the model, verifies SHA256 against the committed hash, writes to the XDG path; runs on Linux and macOS CI matrix
- [ ] `tests/perceptual_mos/sample_rate_normalization.rs` — input streams at 8k (G.711), 16k, 24k, 48k all produce comparable NISQA scores (within 0.2 MOS) for the same underlying signal — proves resampling is not corrupting the score
- [ ] CI workflow `.github/workflows/cross-build-perceptual.yml` — `cross build --features perceptual_mos --target x86_64-unknown-linux-musl` and `--target aarch64-unknown-linux-gnu` both succeed
- [ ] `tests/perceptual_mos/license_audit.rs` — `cargo deny check` passes with NISQA's MIT license and ONNX Runtime's MIT license accounted for

**Docs — 11.2 deliverables:**
- [ ] `docs/perceptual-mos.md` — what NISQA is, how it differs from E-model, when each is more trustworthy, model download instructions, performance characteristics, divergence interpretation
- [ ] Update `docs/rtp-quality.md` (Phase 5 doc) with the dual-MOS framework
- [ ] Update `docs/mcp-tools.md` `rtp_stats` entry to document the new `perceptual_mos` field

---

## Phase 12 — Documentation & Website Overhaul

**Goal:** Replace the ad-hoc current documentation (10 reference files, no tutorials, no how-tos, no concepts, no glossary, no IA, unknown website state) with a versioned, searchable, audience-organized documentation system that scales from a 10-doc baseline to the 35+ docs the rest of this roadmap will produce.

**Milestone (12.1–12.2):** new docs site live at `sipnab.com/docs/` (or equivalent), Diátaxis taxonomy defined, sidebar navigation reflecting the eventual structure, all existing 10 docs migrated and re-categorized, search and versioning working.

**Milestone (12.3–12.7):** every existing CLI flag, MCP tool, REST endpoint, and config option has reference documentation; at least three audience-targeted tutorials exist; concept pages cover architecture, design philosophy, comparisons against sngrep/sipgrep/Pcaptix; cookbook holds at least 12 how-to recipes drawn from across the roadmap.

**Release target:**
- 12.1, 12.2 (★ priority): **before Phase 8.6 ships** — so all Phase 8 docs land in the new structure from day one. Roughly aligned with v0.4.0-rc1.
- 12.3–12.7: progressive, completing by **v0.5.0** general availability.

**Exit criteria — Phase 12 is done when:**
- [ ] Docs site is live with versioning (v0.3, v0.4, v0.5+, "main"/dev)
- [ ] Every CLI flag in `cli.rs` appears in `docs/cli-reference.md` (CI-enforced)
- [ ] Every MCP tool registered in `src/mcp/server.rs` has a documentation page (CI-enforced)
- [ ] Every REST endpoint has an OpenAPI spec entry (gated by Phase 9.1 — interlocks with this phase)
- [ ] At least three tutorials exist, each completable end-to-end in under 15 minutes by someone new to sipnab
- [ ] Glossary covers SIP/RTP/SDP terminology that appears in the docs (PDD, MOS, SBC, B2BUA, etc.)
- [ ] Comparison page exists comparing sipnab against sngrep, sipgrep, and Pcaptix on a feature matrix
- [ ] Link checking and spell checking pass in CI
- [ ] Every public Rust API in `lib.rs` has rustdoc — `cargo doc --no-deps` produces complete coverage
- [ ] Search works (Algolia DocSearch or built-in lunr.js fallback)
- [ ] Mobile rendering is acceptable (responsive layout, no horizontal scroll on narrow viewports)

---

### 12.1 — ★ Site Infrastructure (PRIORITY)

Stand up the documentation system. Must complete before Phase 8 doc deliverables start landing, so new content from Phase 8 onward goes into the new system from day one.

**Static site generator choice:**
- **Recommendation: mkdocs-material.** Mature, batteries-included for technical docs, excellent navigation/search, mature versioning via `mike`, clean default theme that requires minimal customization. The de facto standard for technical software documentation. Python-based but produces a fully static HTML site; CI builds and publishes the artifact, no Python runtime needed for users.
- **Alternative considered: mdBook.** Rust-native, integrates cleanly with rustdoc. Wins on aesthetic alignment with the Rust ecosystem. Loses on versioning (no first-class story), search (basic), and theming flexibility. Worth choosing only if there's a strong reason to keep all tooling in the Rust ecosystem.
- **Alternative considered: Docusaurus.** React-based, batteries-included, excellent versioning. Heaviest dependency footprint, requires Node.js in CI. Pick this only if interactive docs (live React components, embedded playgrounds) become a need — unlikely for sipnab.
- **Decision required from maintainer:** confirm mkdocs-material or specify alternative. Open Question #6 below.

**Tasks:**
- [ ] **★ Audit `website/` first (0.5 day, blocks the rest of 12.1).** Inventory the directory's current state: which SSG (if any), which pages exist, deployment target, custom theme/JS/build process. Output is a one-page audit doc in `tasks/website-audit.md`. The audit either confirms there's no material existing investment (proceed with mkdocs-material) or surfaces an existing toolchain (Hugo, Astro, Docusaurus, etc.) that 12.1 should migrate within rather than replace.
- [ ] **Pick the SSG based on the audit outcome.** Default: mkdocs-material with `mike` for versioning and Algolia DocSearch for search. Override only if the audit finds an existing investment worth preserving (and document that choice in `tasks/website-audit.md`).
- [ ] **Repository layout:** `docs/` for content (existing), `mkdocs.yml` (or chosen SSG's config) at repo root, `website/` for any non-docs marketing pages (homepage, blog). The Rust code's `cargo doc` output goes to `docs/api/` (subdomain or path-mounted)
- [ ] **Theme and branding:** mkdocs-material with the existing color palette (consistent with the TUI theme); custom logo (commission or generate); favicon
- [ ] **Versioning:** `mike` plugin set up with versions for current released sipnab (v0.3) and future releases. Default landing page redirects to the latest stable. `main` branch builds publish to `/dev/`.
- [ ] **Search:** Algolia DocSearch (free tier for OSS); fall back to mkdocs-material's built-in lunr.js if Algolia application is delayed
- [ ] **Hosting:** Cloudflare Pages, GitHub Pages, or Netlify (operator's choice). Auto-deploy on push to `main`; preview deployments for PRs
- [ ] **CI:** `.github/workflows/docs.yml` builds the site on every PR; deploys on merge to `main`. Failed builds fail the PR.
- [ ] **404 page:** custom, with search and a link back to the index
- [ ] **OpenAPI spec hosting:** Phase 9.1's `openapi.json` published to `sipnab.com/api/openapi.json` and rendered via Swagger UI at `sipnab.com/api/` — this interlocks with Phase 9.1 (Phase 12.1 sets up the hosting; Phase 9.1 produces the content)
- [ ] **Rustdoc hosting:** `cargo doc --no-deps` output published to `sipnab.com/api/rust/` per release
- [ ] **★ CI quality gates land with 12.1, not 12.4.** Every Phase 8/9 PR after 12.1 ships gets these gates, so docs gaps don't accumulate during the long content-writing tail of Phase 12. The gates are mechanical (no content judgment), so they can land before any Diátaxis classification or content rewrite. Specifically:
  - **CLI flag coverage check** — script that parses `cli.rs` for `#[arg(long = "...")]` and verifies each appears in `docs/cli-reference.md` (or its eventual `docs/reference/cli-reference.md` location). Fails CI when a flag is added without docs.
  - **MCP tool coverage check** — script that parses `src/mcp/server.rs` for `#[tool]` annotations and verifies each has an entry in the MCP tool reference. Fails CI on mismatch.
  - **MCP tool description lint** (already specified in 8.1) — runs the same imperative-verb regex from 8.1 in the docs CI workflow as a defense-in-depth check.
  - **Link checker** — `lychee` or `markdown-link-check` against all docs and the rendered site; broken internal/external links fail the PR.
  - **Spell checker** — `cspell` with a project dictionary (`SIP`, `RTP`, `OpenSIPS`, etc. allowlisted); fails on unknown words.
  - **Code-block validation** — extract bash/toml/json code blocks from docs and validate syntax (catches typos in examples).
  - **Rustdoc coverage** — `cargo doc --no-deps`; CI fails if any public item lacks rustdoc.

**Gate — 12.1 is done when:**
- [ ] Docs site is reachable at sipnab.com/docs/ (or equivalent agreed URL)
- [ ] Versioning works: switching versions in the UI shows the right version's docs
- [ ] Search finds content from at least three different docs
- [ ] Push to `main` deploys to `/dev/` within 5 minutes
- [ ] PR preview deploys produce a unique URL within 5 minutes
- [ ] Mobile (narrow viewport) renders cleanly with no horizontal scroll
- [ ] All existing 10 docs render correctly in the new system without changes (lift-and-shift)

**Docs — 12.1 deliverables:**
- [ ] `docs/contributing/docs-workflow.md` — how to add a new doc, how to preview locally, how to use the Diátaxis classifications, how versioning works
- [ ] `mkdocs.yml` (or equivalent) committed and documented inline

---

### 12.2 — ★ Information Architecture (PRIORITY)

Establish the taxonomy that all future docs follow. Audit existing content. Define the sidebar structure for the eventual ~35-doc state.

**Adopt Diátaxis (D23 reference):**
The four-quadrant framework (tutorials / how-to guides / reference / explanation) is the de facto standard for technical documentation IA. It's load-bearing because each doc has one and only one slot, which prevents the "is this a tutorial or a reference?" debates that turn doc trees into mush.

- **Tutorials** — learning-oriented, hand-held, "if you follow this exactly, you will succeed and learn." Focus: the *learner's experience.*
- **How-to guides** — problem-oriented, recipe-style, "to accomplish X, do these steps." Focus: the *task being done.*
- **Reference** — information-oriented, exhaustive, accurate, dry. Focus: *the artifact* (API, CLI, config).
- **Explanation** — understanding-oriented, conceptual, philosophical. Focus: the *background and rationale.*

**Tasks:**
- [ ] **Sidebar structure** drafted in `mkdocs.yml`:
  ```
  Home
  Getting Started (tutorials)
    - Install sipnab
    - Your first capture
    - Analyze a pcap with the TUI
    - Talk to sipnab from an AI agent (MCP quickstart)
  Guides (how-tos)
    - Diagnose one-way audio
    - Detect SIP scanners
    - Run sipnab as a daemon
    - Decrypt TLS-encrypted SIP
    - Stream events to Grafana via SSE
    - [grows as cookbook fills out — Phase 12.6]
  Reference
    - CLI reference
    - Configuration reference
    - Filter DSL reference
    - MCP tool reference
    - REST API reference (OpenAPI)
    - Keybindings (TUI)
    - Diagnostic aliases
    - Glossary
  Concepts (explanation)
    - Architecture overview
    - Capture pipeline
    - Dialog state machine
    - RTP quality model (E-model + perceptual MOS)
    - Security model
    - Comparison: sipnab vs sngrep vs sipgrep vs Pcaptix
    - Design philosophy and non-goals
  Deployment
    - Single-host
    - Daemon mode (systemd)
    - Distributed (HEP collector + edge senders)
    - Observability stack (OpenTelemetry + Tempo + Prometheus)
  Development
    - Building from source
    - Contributing
    - Architecture (internals)
    - Release process
  ```
- [ ] **Content audit** — every existing doc gets classified into one Diátaxis quadrant. Existing docs are mostly Reference; this surfaces the missing tutorials, how-tos, and explanation pages
- [ ] **Doc templates** — one template file per quadrant in `docs/_templates/` (tutorial.md, howto.md, reference.md, explanation.md). New docs start by copying a template
- [ ] **Front-matter convention:** every doc has YAML front-matter with `category: tutorial|howto|reference|explanation`, `audience: voip-engineer|security-analyst|agent-developer|all`, `version_added: 0.4`. Front-matter is rendered as breadcrumbs / badges
- [ ] **Doc style guide** — `docs/contributing/style-guide.md`: voice (active, second-person), terminology (always "dialog" not "call" in technical contexts; always "MOS" expanded once per page), length, code block conventions, link conventions

**Gate — 12.2 is done when:**
- [ ] All 10 existing docs are classified and have front-matter
- [ ] Sidebar structure is implemented in `mkdocs.yml` and visually scannable
- [ ] Doc templates exist and are documented in the docs-workflow guide
- [ ] Style guide is published and at least one existing doc has been refactored to demonstrate it

**Docs — 12.2 deliverables:**
- [ ] `docs/contributing/style-guide.md`
- [ ] `docs/contributing/diataxis.md` — explanation of the framework, how to choose a quadrant, examples
- [ ] `docs/_templates/{tutorial,howto,reference,explanation}.md`

---

### 12.3 — Tutorials & Quickstart

Three audience-targeted tutorials, each completable in under 15 minutes by someone new to sipnab. Tutorials are the riskiest content category (they have to *just work* end-to-end with no clarifying questions) but pay off the most for onboarding.

**Audiences:**
- **VoIP engineer** — runs OpenSIPS/Asterisk/FreeSWITCH, has a problem call to diagnose, never used sipnab
- **Security analyst** — runs SBCs facing the public internet, wants to detect scanners and toll fraud
- **AI agent operator** — wants to wire sipnab into a Claude/GPT agent for SIP debugging

**Tasks:**
- [ ] **Tutorial 1: "Your first sipnab analysis"** (VoIP engineer audience)
  - Install sipnab via the .deb package
  - Capture 30 seconds of live traffic with `sudo sipnab -d eth0`
  - Walk through the TUI: call list, call flow ladder, RTP quality view
  - Diagnose a sample one-way audio call (use a bundled demo pcap)
  - Export findings as a call report
- [ ] **Tutorial 2: "Detect SIP scanners on a public-facing SBC"** (security analyst audience)
  - Install sipnab in daemon mode
  - Configure `--kill-scanner` and `--alert syslog`
  - Walk through what gets detected and why (User-Agent patterns, REGISTER scanning, fraud heuristics)
  - Wire alerts into fail2ban
- [ ] **Tutorial 3: "Drive sipnab from an AI agent"** (agent operator audience)
  - Install sipnab with `--features mcp`
  - Configure systemd unit for `sipnab --mcp --mcp-transport http`
  - Connect Claude Code (or equivalent) to the MCP server
  - Walk through three example agent prompts: "find calls with quality issues in the last hour," "give me a call report for Call-ID X," "what's wrong with this customer's complaint"
- [ ] **Each tutorial includes:**
  - Prerequisites box at the top
  - Time estimate
  - Inline expected-output blocks so the reader knows when they've succeeded
  - Troubleshooting section for common failure modes
  - "What's next" linking to relevant how-tos and reference

**Gate — 12.3 is done when:**
- [ ] All three tutorials are written and reviewed end-to-end by someone who hasn't seen sipnab before (or, failing that, by Claude in a fresh context — the gate is "completable without external help")
- [ ] Each tutorial has a CI smoke test that runs the commands and verifies expected output (where feasible — some live-capture commands can't be CI'd)
- [ ] Tutorial pages link forward to the next logical step

**Docs — 12.3 deliverables:**
- [ ] `docs/getting-started/install.md` (renamed/restructured from existing `docs/install.md`)
- [ ] `docs/getting-started/your-first-capture.md`
- [ ] `docs/getting-started/analyze-a-pcap.md`
- [ ] `docs/getting-started/mcp-quickstart.md`
- [ ] `docs/getting-started/scanner-detection-tutorial.md`

---

### 12.4 — Reference Completeness

Make every flag, every tool, every config option, every endpoint reference-documented. **The CI coverage gates that enforce 100% coverage land with 12.1**, not here — 12.4 is the content-completion sub-phase that the gates already in place will accept. By the time 12.4 starts, the gates are red on every gap; 12.4's job is to fill the gaps and turn the gates green.

- [ ] **CLI reference content** — current `docs/cli-reference.md` is 218 lines, well-structured, but missing the new flags from Phases 8–11. Audit-and-fill: every flag in `cli.rs` must appear in the reference. (The CLI-flag-coverage CI gate already enforces this from 12.1 onward; 12.4 closes the existing gap.)
- [ ] **MCP tool reference content** — `docs/reference/mcp-tools.md` (consolidated from Phase 8's `docs/mcp-tools.md`): one section per tool with parameters, return shape, examples, errors. (The MCP-tool-coverage CI gate from 12.1 enforces presence; 12.4 fills in the per-tool detail.)
- [ ] **REST API reference** — `docs/reference/rest-api.md` is now Swagger UI rendered from Phase 9.1's `openapi.json`. Static page links to the live Swagger UI with a "for offline reference, see openapi.json" link.
- [ ] **Config reference** — current `docs/config-reference.md` extended with new `[limits.asymmetry]` section from Phase 8.7, snapshot resource limits from 8.3, etc. (NATS config dropped — Phase 10 deferred.)
- [ ] **Filter DSL reference** — current `docs/filter-dsl.md` extended with the six new asymmetry fields from Phase 8.7
- [ ] **Diagnostic aliases reference** — new `docs/reference/diagnostic-aliases.md` consolidating the `--problems`/`--slow-setup`/`--one-way`/etc. plus the six new aliases from Phase 8.7
- [ ] **Glossary** — new `docs/reference/glossary.md` covering SIP terminology (Call-ID, dialog, transaction, branch, tag, B2BUA, SBC, registrar, proxy, redirect, UAS, UAC), RTP terminology (SSRC, payload type, ptime, jitter, MOS, R-factor, codec, ptime, DTMF, DTX, CN, RFC 4733), SDP terminology (offer/answer, m-line, c-line, a=rtpmap, a=ptime), security terminology (digest, nonce, STIR/SHAKEN, attestation, PASSporT, fraud, IRSF, scanner). Cross-linked from every doc that uses these terms.
- [ ] **Keybindings** — current `docs/keybindings.md` audited against actual TUI keybindings; CI script extracts keybindings from TUI source and validates
- [ ] **Configuration cookbook** — `docs/reference/config-examples.md` with annotated example configs for common deployments

**Gate — 12.4 is done when:**
- [ ] All CI coverage gates from 12.1 pass green on the existing codebase (no missing flags, no missing MCP tool entries, no broken links, no rustdoc gaps)
- [ ] Glossary covers every SIP/RTP/SDP/security term that appears more than once in the docs
- [ ] Every reference doc links forward to relevant how-tos and tutorials

**Docs — 12.4 deliverables:** all of the above reference docs.

---

### 12.5 — Concepts & Explanation

Explain *why* sipnab is the way it is. The current docs explain *what* sipnab does and *how* to use it; nothing explains the design philosophy, the architecture, or the comparisons that help users decide whether sipnab is right for them.

- [ ] **Architecture overview** — `docs/concepts/architecture.md`: high-level diagram of capture → parse → dialog/RTP store → output backends (TUI/CLI/JSON/MCP/REST/event bus). Text walk-through. Cross-links to the source modules.
- [ ] **Capture pipeline** — `docs/concepts/capture-pipeline.md`: how packets flow from libpcap through the parser into the dialog store. Explains the crossbeam channel, the rendezvous-before-priv-drop pattern, multi-device capture, HEP receiver mode.
- [ ] **Dialog state machine** — `docs/concepts/dialog-state.md`: the SIP dialog states sipnab tracks (Trying, Proceeding, Early, InCall, Completed, Failed, Cancelled), state transitions, retransmission detection, the eviction policy. Diagram.
- [ ] **RTP quality model** — `docs/concepts/rtp-quality.md`: how sipnab calculates network MOS (E-model G.107), how perceptual MOS (NISQA, Phase 11.2) differs, when each is more trustworthy, the divergence interpretation framework.
- [ ] **Security model** — `docs/concepts/security-model.md`: privilege drop, process isolation, defense-in-depth limits, decryption material handling, MCP/REST authentication, the redaction options. References D15–D19.
- [ ] **Design philosophy and non-goals** — `docs/concepts/philosophy.md`: what sipnab is and isn't. Adapted from v6 plan's Non-Goals section, written for a public audience. Why the TUI matters. Why MCP not gRPC. Why open source.
- [ ] **Comparison pages**:
  - `docs/concepts/vs-sngrep.md` — sipnab is the spiritual successor to sngrep with what's added; honest about what sngrep still does better (smaller binary, simpler install)
  - `docs/concepts/vs-sipgrep.md` — feature equivalence and additions
  - `docs/concepts/vs-pcaptix.md` — sipnab vs commercial Pcaptix; honest assessment of where each fits (CLI vs desktop, security analysis vs voice QoE specialty)
  - `docs/concepts/vs-wireshark.md` — sipnab is not a Wireshark replacement; it generates tshark commands to bridge

**Gate — 12.5 is done when:**
- [ ] Architecture overview includes a diagram (rendered in the site, not just ASCII art in markdown)
- [ ] Comparison pages have honest "where the other tool wins" sections — not marketing copy
- [ ] Philosophy page explains the three release-blocking design decisions (TUI-first, MCP-not-gRPC, source-vs-enrichment) in language a new evaluator would understand

**Docs — 12.5 deliverables:** all of the above concept docs.

---

### 12.6 — How-to Cookbook

Recipe-style how-to guides for specific tasks. Drawn from the diagnostic recipes scattered through Phases 8–11. The cookbook is the "search-engine destination" surface — most users land here from Google searching for "how do I do X with sipnab."

- [ ] **Existing recipes consolidated** from across the roadmap into `docs/howto/`:
  - `diagnose-one-way-audio.md`
  - `diagnose-codec-asymmetry.md` (Phase 8.7)
  - `diagnose-late-media.md` (Phase 8.7)
  - `diagnose-customer-complaint.md` (Phase 8.6 demo)
  - `extract-pcap-for-call-id.md`
  - `tail-problems-as-they-happen.md`
  - `find-calls-with-bad-mos.md`
  - `compare-network-vs-perceptual-mos.md` (Phase 11.2)
  - `analyze-feature-importance.md` (Phase 11.1)
  - `detect-scanners.md`
  - `detect-toll-fraud.md`
  - `decrypt-tls-sip.md`
  - `decrypt-srtp-with-keylog.md`
  - `set-up-as-systemd-daemon.md`
  - `wire-sipnab-into-grafana.md`
  - `wire-sipnab-into-fail2ban.md`
- [ ] **Standard format:** problem statement, prerequisites, step-by-step, expected output, troubleshooting, related how-tos and concepts
- [ ] **Cross-linked aggressively** — each how-to links to the relevant reference and concept docs

**Gate — 12.6 is done when:**
- [ ] At least 12 how-to recipes exist
- [ ] Each follows the standard format
- [ ] Site search returns at least one relevant how-to for common task queries ("one-way audio," "decrypt TLS," "scanner detection")

**Docs — 12.6 deliverables:** all of the above how-to recipes plus a `docs/howto/index.md` overview page.

---

### 12.7 — Website / Marketing Surface, Quality Tooling, Launch

Beyond docs, the website itself needs a homepage, comparison narrative, deployment showcase, and the quality-tooling infrastructure that enforces D23 going forward.

**Marketing surface:**
- [ ] **Homepage redesign** — clear positioning ("SIP & RTP capture, analysis, and security — replaces sngrep + sipgrep with one binary, plus AI-agent-callable analysis"), three-feature highlight, install command, GitHub stars, license badges, screenshot of the TUI
- [ ] **Feature page** — `/features/` — bulleted feature list with screenshots/diagrams
- [ ] **Comparison page** — `/compare/` — sipnab vs sngrep / sipgrep / Pcaptix / Wireshark feature matrix; honest about what sipnab does and doesn't do
- [ ] **Deployment showcase** — `/deployments/` — case-study-style pages showing single-host, fleet, observability-stack, AI-agent topologies
- [ ] **Blog** — minimal, optional. If included, first post is the OpenSIPS Summit follow-up referenced in Phase 8.6

**Quality tooling (12.7 adds the marketing-surface gates only — content gates landed with 12.1):**
- [ ] **Mobile rendering check** — Lighthouse CI against the deployed PR preview; fails on accessibility/mobile-rendering regressions
- [ ] **Homepage performance gate** — Lighthouse Performance score > 90 on a cold cache for the marketing homepage

> *The link checker, spell checker, CLI flag coverage check, MCP tool coverage check, MCP tool description lint, code-block validation, and rustdoc coverage gates already shipped with 12.1 — they've been catching gaps since before 12.7 starts. 12.7 only adds the marketing-page-specific Lighthouse checks here.*

**Launch:**
- [ ] **Announcement post** — short blog post or README banner: "v0.4.0 ships with new docs site"
- [ ] **OpenSIPS Summit follow-up post** referenced in Phase 8.6 — point to the new docs site as the primary reference
- [ ] **CHANGELOG.md** entry for the docs overhaul itself

**Gate — 12.7 is done when:**
- [ ] Homepage loads in under 1 second on a cold cache (Lighthouse Performance score > 90)
- [ ] Comparison page exists and has been reviewed for accuracy by someone who knows the competitors
- [ ] Mobile rendering passes Lighthouse Accessibility check
- [ ] All 12.1 CI quality gates remain green at the time 12.7 ships (regression check)

**Docs — 12.7 deliverables:**
- [ ] All marketing pages above
- [ ] CI workflow files for each quality check
- [ ] `docs/contributing/quality-gates.md` — explains what each CI check enforces

---

## Implementation Gotchas (cross-cutting)

These are spread across phases above but consolidated here as a checklist for code review and for the `tasks/lessons.md` file after implementation.

### Gotcha 1 — Stdio mode: stdout is the JSON-RPC wire

**Symptom if violated:** MCP client sees parse errors after the first `log::info!` from the capture or parser path. Subtle, intermittent, looks like a client bug.

**Mitigations:**
- `serve_stdio` re-initializes `env_logger` with `Target::Stderr` regardless of `RUST_LOG` config
- Audit `src/sip/parser.rs`, `src/capture/parse.rs`, and `src/capture/reassembly.rs` for stray `println!`/`eprintln!` (none should exist; the codebase already uses `log::*`, but verify)
- Add a CI test that runs `sipnab --mcp -I <large.pcap>` with `RUST_LOG=trace` and asserts every line on stdout parses as JSON-RPC
- Document in `src/mcp/transport.rs::serve_stdio` rustdoc

### Gotcha 2 — Privilege drop sequencing

**Symptom if violated:** MCP HTTP transport fails with `EACCES` on bind (when binding privileged port), OR sipnab continues running as root past initial startup, OR capture fd is closed before MCP server starts.

**Mitigations:**
- MCP HTTP socket bound in the same window as the existing API socket: after capture-ready signal (`main.rs:387`), before `privilege::drop_privileges` (`main.rs:439`)
- The capture readiness rendezvous channel pattern (`ready_tx`/`ready_rx`) is reused — MCP gets its own readiness signal so the main thread can wait for both capture and MCP listener before dropping privileges
- nginx is the recommended path for any privileged port (443) — sipnab itself binds unprivileged
- Document the bind-before-drop invariant in `src/mcp/transport.rs::serve_http` rustdoc
- Gate test: `ps -o user,pid` after startup confirms non-root user

### Gotcha 3 — `parking_lot` guards across `.await`

**Symptom if violated:** Deadlock under concurrent MCP tool calls (two MCP requests in flight, plus the capture thread, can produce a three-way deadlock). Hard to reproduce locally with one client, easy to hit in production with a chatty agent.

**Mitigations:**
- The existing `output::api` handlers (`list_dialogs` at `api.rs:349`, `get_dialog` at `api.rs:406`, etc.) already follow the correct pattern: `read()` → snapshot/clone → explicit `drop(ds)` → `.await` happens after the drop. MCP handlers must mirror this.
- Add `#![deny(clippy::await_holding_lock)]` to `src/mcp/server.rs` and `src/mcp/transport.rs`
- Code review checklist item for any `parking_lot::RwLockReadGuard` / `RwLockWriteGuard` lifetime that crosses an `await` point in the MCP module
- Document in `src/mcp/server.rs` module-level rustdoc, with a worked correct/incorrect example
- Stress test in 8.3 gate: 100 concurrent tool calls during active capture for 60 seconds, no deadlock detected
- **Phase 9.2 extension:** the same rule applies to any function newly decorated with `#[tracing::instrument]` if the function holds a parking_lot guard and awaits inside the span. Audit OTel instrumentation in 9.2 against the same clippy lint.

### Gotcha 4 — OTel instrumentation on the parse hot path (Phase 9.2)

**Symptom if violated:** Adding `#[tracing::instrument]` to `parse_packet` and `parse_sip` without subscriber-level filtering tanks throughput by 30–50% even when no exporter is attached. Span construction is not free — the `Span` and its attributes are allocated regardless of whether the subscriber drops them.

**Mitigations:**
- Use `tracing::span!(Level::TRACE, ...)` for hot paths (`parse_packet`, individual SIP header parses) and configure the global `EnvFilter` to reject TRACE level by default
- Use `Level::DEBUG` for medium-frequency paths (`process_message`, `update_state`)
- Use `Level::INFO` only for low-frequency operations (capture session start, dialog terminal state, MCP tool entry/exit)
- Spans below the active filter level are zero-cost in `tracing` 0.1+ — they compile down to a single comparison
- Performance gate in 9.2 requires throughput regression ≤ 5% with `otel` feature compiled in but no exporter active
- Document the level-per-path convention in `src/mcp/server.rs` and `docs/observability.md`

---

## Open Questions for Resolution Before Implementation

These need a yes/no from the maintainer before 8.1 starts; default answers are listed.

1. **Default port for `--mcp-bind`:** suggested `127.0.0.1:8731` (mnemonic: 8 = transport layer, 731 = "SIP" on a phone keypad). Acceptable, or pick another?
2. **Coexistence with `--api`:** when both are set with the same bind, mount MCP at `/mcp` on the existing Router (recommended) vs. require different ports (simpler). Default: mount on shared Router.
3. **License of MCP-related contrib scripts:** match the dual MIT/Apache-2.0 of the main crate. Confirm no external libs in `gen-mcp-token.sh` introduce a different license.
4. **HEP-over-NATS demand?** Phase 10 (NATS) is now deferred to Future Considerations (see below). Decision needed only if Phase 10 is later triggered: is `--hep-nats-subject` useful for deployments where edge SBCs publish HEP via NATS, or is the existing UDP `--hep-listen` sufficient? Default: defer to Future Considerations until a concrete deployment asks for it.
5. **★ Static site generator for Phase 12.1:** resolved with a 0.5-day audit pre-task in 12.1 itself (audit `website/` current state, then commit to mkdocs-material unless the audit finds material existing investment in another SSG).

> *Note: the prior "security_findings history retention" question is resolved — the `AlertEngine::FindingsHistory` ring buffer task is in 8.3 with a documented default of 1000 entries and a `--mcp-findings-retain` override.*

---

## Estimated Effort

Single-developer estimate, calibrated to v6 conventions. **★** marks the priority items called out in the Priority Sequencing callout.

### Phase 8 (v0.4.0 — MCP)

| Sub-phase | Effort | Notes |
|---|---|---|
| 8.0a — Parse-path consolidation | 1–2 days | Eliminates batch+API double-parse; prerequisite to a clean EventBus |
| 8.0b — log → tracing mechanical migration | 1 day | No spans yet; preserves stdio MCP's stderr-only logging invariant |
| 8.1 — Skeleton + stdio + 3 tools + tool-description lint + feature-matrix CI | 3–4 days | Was 2–3d; +0.5d for the description lint task and +0.5d for the matrix CI workflow |
| 8.2 — HTTP transport + systemd + token-rotation docs | 2 days | Reuses 80% of existing api.rs infrastructure; rotation-restart documented (no hot reload in v0.4) |
| 8.3 — Full tool surface (incl. snapshot resource limits, tail_dialogs EOF, FindingsHistory ring buffer) | 3–4 days | 8 tools × ~half day each, including bounding |
| 8.4a — Event Bus substrate (feature-gated) + Loom test | 2–3 days | Substrate-only; preserves sync ExecSink path |
| 8.4b — MCP notifications + WebSocket + SSE sinks | 3 days | +1d each for WS and SSE on top of MCP notifications (was +0.5d — backpressure + Last-Event-ID resume aren't trivial) |
| 8.5 — HEP + multi-source | 1 day | Mostly testing — code paths exist |
| 8.6 — Polish, demos, release ★ | 4.5–5.5 days | Includes ★ quality timeline bump (0.5–1d) and ★ `.sipnab` project file **2–3d** (was 1d — DialogStore/StreamStore aren't currently `Deserialize`; rehydration is the missing inverse) |
| 8.7 — ★ Per-call asymmetry heuristics | 4–5 days | ★ PRIORITY — five trivial checks plus `one_sided_silence` at **1.5–2d** alone (codec-aware energy, DTX/CN handling) |
| **Phase 8 total** | **24.5–30.5 days** | ~5–6 weeks of solo work (was ~4 weeks; the 8.0 prerequisite plus tightened 8.6/8.7/8.4 estimates account for the delta) |

Phase 8.0 lands the parse-path and tracing cleanups before any sink work; 8.1 ships `--mcp` over stdio with three tools — that alone resolves the issue request for ad-hoc workflows. Phase 8.2 adds the network transport the issue actually wants. Phase 8.7 (PRIORITY) ships the highest-ROI analytical improvement of the entire roadmap. Phases 8.3–8.6 round it out to release quality.

### Phase 9 (v0.5.0 — OpenAPI + OTel)

| Sub-phase | Effort | Notes |
|---|---|---|
| 9.1 — OpenAPI spec + SDK generation | 2–3 days | utoipa annotations + Swagger UI + CI client gen |
| 9.2 — OpenTelemetry tracing + metrics | 5–7 days | Was 3–4d. Span hierarchy + W3C `traceparent` extraction during parse + `tracing-prometheus` integration + WASM/feature combo verification realistically don't fit in 4 days. The mechanical log→tracing migration moved to Phase 8.0, so 9.2 is span work + exporter wiring only. |
| **Phase 9 total** | **7–10 days** | ~1.5–2 weeks |

### Phase 10 — NATS Event Bus (deferred)

Effort line removed. Phase 10 is deferred to Future Considerations. When the trigger condition fires, scope is ~2–3 days given the 8.4a substrate exists; budget is allocated then, not now.

### Phase 11 (v0.6.0 — Statistical Analysis & Perceptual MOS)

| Sub-phase | Effort | Notes |
|---|---|---|
| 11 — ★ Design pass | 2–3 days | ★ PRIORITY — write design before Phase 8 ships, build later |
| 11.1 — Cross-stream statistical analysis | 4–5 days | linfa regression, partition-by-subnet, MCP tool |
| 11.2 — Perceptual MOS via NISQA | 12–16 days | Was 8–10d. ONNX runtime musl prebuilts don't exist (build-from-source is 2–3d alone); subjective-rating corpus sourcing is multi-day; sample-rate normalization correctness validation is non-trivial |
| **Phase 11 total** | **18–24 days** | ~4–5 weeks; design upfront, build deferred until after Phase 8 |

### Phase 12 (Threaded across v0.4.0–v0.6.0 — Documentation & Website Overhaul)

| Sub-phase | Effort | Notes |
|---|---|---|
| 12.1 — ★ Site infrastructure + CI quality gates | 3–4 days | ★ PRIORITY — 0.5d `website/` audit pre-task + SSG + versioning + search + CI; coverage/link/spell/code-block/rustdoc gates land here, not 12.4 |
| 12.2 — ★ Information architecture | 1–2 days | ★ PRIORITY — Diátaxis taxonomy, content audit, sidebar, templates |
| 12.3 — Tutorials & quickstart | 3–4 days | Three audience-targeted tutorials (VoIP eng, security analyst, agent operator) |
| 12.4 — Reference completeness | 2–3 days | CLI/MCP/REST/config/glossary content fill (gates already in place from 12.1) |
| 12.5 — Concepts & explanation | 3–4 days | Architecture, design philosophy, comparisons, security model |
| 12.6 — How-to cookbook | 2 days | 12+ recipes consolidated from across phases |
| 12.7 — Marketing surface + Lighthouse gates + launch | 2–3 days | Was 3–4d (CLI/MCP coverage gates moved to 12.1); 12.7 is now homepage + comparison page + Lighthouse Performance/Accessibility checks + announcement |
| **Phase 12 total** | **16–22 days** | ~4 weeks total, threaded across Phase 8/9/11 timelines (3.5–6d upfront, rest progressive) |

### Combined roadmap effort

| Stage | Effort | Cumulative | Calendar timing |
|---|---|---|---|
| Phase 12.1–12.2 (★ priority — docs infrastructure + IA + CI gates) | 4–6 days | 4–6 days | **Before** Phase 8 starts |
| Phase 8.0 (prerequisite cleanups: parse-path + log→tracing) | 2–3 days | 6–9 days | First thing in Phase 8 |
| Phase 8 (v0.4.0, includes 8.0; ★ 8.6 expansion + ★ 8.7) | 22.5–27.5 days net (after 8.0) | 28.5–36.5 days | After 12.1–12.2 |
| Phase 11 design (★ priority) | 2–3 days | 30.5–39.5 days | Concurrent with Phase 8 (one focused week) |
| Phase 12.3–12.6 (docs content, progressive) | 10–13 days | 40.5–52.5 days | Threaded across Phase 8/9 |
| Phase 9 (v0.5.0) | 7–10 days | 47.5–62.5 days | After Phase 8 |
| Phase 12.7 (marketing surface + Lighthouse + launch) | 2–3 days | 49.5–65.5 days | Aligned with v0.5.0 launch |
| Phase 11 build (v0.6.0) | 16–21 days | 65.5–86.5 days | After Phase 9 |
| Phase 10 (deferred) | — | 65.5–86.5 days | Future Considerations — no current allocation |

**Priority work alone (★ items): ~12–17 days threaded across the first ~7 weeks** (Phase 12.1–12.2 + 8.0 upfront, then Phase 8.6/8.7 expansions and Phase 11 design pass during Phase 8).

**Realistic calendar:** ~16–20 weeks of solo work end-to-end through v0.6.0 (was 13–16). The growth comes from: Phase 8.0 prerequisites (~3 days), tightened 8.6/8.7/8.4 estimates (~3–5 days), Phase 9.2 realism (~3 days), and Phase 11.2 musl/corpus realism (~4–6 days). Compressible if Phase 12 content work runs in parallel with Phase 8/9 build work (different cognitive modes — coding and writing rarely block each other on the same day).

---

## Future Considerations (Beyond Phase 10)

This section catalogs ideas that have been evaluated and deferred — not rejected. They are written down so they don't have to be re-derived when a concrete need arises, and so future contributors don't waste time relitigating decisions.

Each item lists the trigger condition (what would have to be true for this to become a phase) and the rough scope (what building it would entail). Items are governed by D21 — they are sorted into capture sources (alternative ways to get SIP/RTP packets) and enrichment sources (structured non-packet context that augments packet-level analysis).

### Capture source candidates (deferred)

**HEP-over-NATS (`--hep-nats-subject`)**
- *Trigger:* Phase 10 is in production, AND a deployment site has edge SBCs publishing HEP to NATS rather than (or in addition to) UDP/TCP HEP.
- *Scope:* ~100 lines reusing Phase 10's `async-nats` connection lifecycle and Phase 1's HEP parse path. Subscribe to a configured NATS subject, pass each message body through the existing HEP parser, feed packets into the same channel as `--hep-listen`. Same Cargo feature (`nats`) gates both publish and subscribe.
- *Why deferred:* the existing UDP/TCP `--hep-listen` covers the standard HEP shipping case. NATS as HEP transport is a deployment optimization, not a missing capability.

**HEP-over-WebSocket (`--hep-ws-listen`)**
- *Trigger:* a deployment site needs HEP through firewalls that only permit HTTP/HTTPS traffic, OR a JavaScript-based capture tool wants to push HEP to sipnab from a browser context.
- *Scope:* ~150 lines on the existing axum stack — accept WebSocket upgrades on a configured path, pass each message body through the existing HEP parser. Reuses bearer auth and rate limiter from Phase 6.
- *Why deferred:* solves a real but narrow firewall-traversal problem. UDP HEP through nginx-as-stream-proxy or stunnel is the simpler workaround for most cases.

**SIPREC SRS mode (`--siprec-srs <bind>`)**
- *Trigger:* a deployment site uses SBC SIPREC recording as the primary method to deliver SIP+RTP to monitoring, with no SPAN port available.
- *Scope:* substantial — sipnab becomes a stateful SIP role (SRS), terminating SIPREC INVITEs, accepting the RTP streams, parsing the multipart metadata, then feeding packets into the parse pipeline. Roughly Phase-1-sized work, with new test infrastructure needed for SBC interop testing. Not a small addition.
- *Why deferred:* large surface area, narrow user base. The existing `src/sip/siprec.rs` parses SIPREC metadata when present in captured INVITEs; that covers most analytical needs without requiring sipnab to be the SRS itself.

### Push sink candidates (deferred)

**NATS sink — full design (deferred from former Phase 10)**
- *Trigger:* (a) An operator with NATS already in production asks for sipnab→NATS, AND (b) their use case is not served by WebSocket or SSE from Phase 8.4b (e.g., they need JetStream replay, or fan-out to >100 subscribers per sipnab instance), AND (c) the Phase 8.4a substrate has been in production and stable for at least one release cycle.
- *Scope:* ~2–3 days given the 8.4a substrate exists. New `nats` Cargo feature pulling `async-nats = "0.40"`. New `NatsSink` implementing `EventSink` from 8.4a. New CLI flags: `--nats-url`, `--nats-creds-file`, `--nats-subject-prefix` (default `sipnab`), `--nats-jetstream`. Subject scheme: `sipnab.dialog.<state>.<call_id>`, `sipnab.rtp.quality.<level>`, `sipnab.security.<kind>`, `sipnab.stats.heartbeat` — hierarchical for wildcard subscription. Same NDJSON envelope as WebSocket/SSE. NATS message headers: `X-Sipnab-Schema-Version`, `X-Sipnab-Source-Host`, `X-Sipnab-Call-Id`, `traceparent` (when otel feature is on). Connection resilience via async-nats's built-in reconnect with exponential backoff. Publish failures increment `nats_publish_failures_total` and never block capture. JetStream support behind `--nats-jetstream` flag for late-joining subscriber replay.
- *Why deferred:* WebSocket and SSE cover the "external systems consume sipnab events" case for the vast majority of deployments without forcing a NATS dependency. Carrying detailed planning for a phase whose trigger may never fire is overhead. The design above is preserved so the work is ready to pick up — until then, no calendar effort.

### Enrichment source candidates (deferred — would be a new phase category)

**OTel trace consumption (Phase 12+ candidate)**
- *Trigger:* OpenSIPS, Asterisk, FreeSWITCH, and adjacent application platforms are emitting OTel spans for SIP transactions with Call-ID as a span attribute (work already underway in OpenSIPS per the OTel module shipped early 2026), AND there's value in correlating sipnab's packet-level call flow with B2BUA-internal routing decisions.
- *Scope:* sipnab queries Tempo (or another OTel trace store) for traces matching a Call-ID, then overlays the upstream spans onto the existing call flow ladder. New `--enrich-otel-endpoint` flag, new `Enrichment` correlation layer alongside `DialogStore`, new TUI rendering for upstream context. MCP and REST tools gain an `include_enrichment=true` parameter that returns the merged view.
- *Why interesting:* no other SIP analyzer does this. sipnab is in a unique position to combine the wire-level truth of packet capture with the decision-level truth of B2BUA spans. Genuinely novel feature, not just plumbing.
- *Why deferred:* meaty design problem (correlation model, TTL on stale spans, partial-match handling, what to do when only one side has trace context). Wants a real design doc and proof-of-concept before committing to a phase. Phase 9.2's W3C `traceparent` propagation lays the foundation; this builds on it.

**Asterisk AMI / FreeSWITCH ESL event consumption**
- *Trigger:* a deployment site needs sipnab analysis to incorporate PBX-internal channel state — hangup causes (`SIP 487 Request Terminated` vs. `Asterisk: caller hung up` are the same event from the wire but different in the PBX), bridge events, codec re-negotiations the PBX initiated, transfer types.
- *Scope:* AMI client (TCP, simple line protocol) for Asterisk; ESL client (TCP, similar) for FreeSWITCH. New `--enrich-ami <host>` and `--enrich-esl <host>` flags. Subscribe to relevant event classes, correlate by Call-ID/UniqueID/UUID against active dialogs, attach as enrichment metadata. Significantly easier than OTel consumption because the protocols are simpler.
- *Why deferred:* useful but narrower than OTel — only applies when sipnab is monitoring a deployment that uses Asterisk or FreeSWITCH (not all do). Can ship after the OTel enrichment design proves out the correlation layer pattern.

**CDR ingestion (post-hoc correlation)**
- *Trigger:* a deployment site has SQL CDR records (from OpenSIPS `acc` table, FreeSWITCH `cdr.csv`, Asterisk `cdr_csv`, or a custom billing schema) and wants sipnab to correlate captured calls against billed calls — "this captured call has no matching CDR" or "this CDR has no matching capture" is a useful audit signal.
- *Scope:* read-only SQL connection (sqlx behind a `cdr` feature), configurable query template, periodic correlation pass. New `--enrich-cdr-url <DSN>` flag. Output is a new `cdr_match: {matched: true, cdr_id: ...}` field on dialog reports.
- *Why deferred:* depends on schema-specific configuration that's deployment-unique. Probably ships as a post-1.0 feature with a documented schema mapping rather than trying to support every possible CDR layout.

### UI / Visualization candidates (deferred — Pcaptix benchmark items)

These are features Pcaptix ships that sipnab evaluated and deferred. Each fits the WASM browser path or a future HTML viewer mode, not the TUI (which can't render waveforms or PDFs natively).

**Waveform display with marker overlay**
- *Trigger:* the WASM browser path (`wasm` feature) or a new HTML-viewer mode in `--api` becomes the primary surface for sharing analyses with non-terminal users (sales engineers, customer support, customers themselves).
- *Scope:* substantial — render decoded RTP audio as a waveform using Web Audio API in the WASM build, overlay marker tracks for re-INVITEs, SIP messages, DTMF events, packet loss bursts, and detected impairments. Coalesce nearby markers automatically. Likely 2–3 weeks of UI work, plus a design pass on the marker model.
- *Why interesting:* this is Pcaptix's most visceral feature. Seeing the loss burst land on the waveform exactly when the call sounds bad is the kind of demo that closes deals.
- *Why deferred:* sipnab's identity is "engineer at terminal," not "QoE specialist at desktop." Adding this is fine if it goes in the WASM path (preserves the no-install story); building a Qt or Electron app to compete with Pcaptix on its own ground is the wrong fight.

**Impairment detection (clipping, noise, echo)**
- *Trigger:* perceptual MOS divergence cases (Phase 11.2) become common enough that operators want sipnab to *explain* the divergence, not just flag it.
- *Scope (clipping):* small. Detect rail-pinned samples in the decoded PCM, count consecutive runs above a threshold. ~1 day. Should ship first as an easy win.
- *Scope (noise floor):* moderate. Estimate noise floor during silence intervals, flag streams with elevated baseline. ~2–3 days.
- *Scope (echo):* research-grade. Real echo detection requires reference-vs-degraded analysis or aggressive autocorrelation. Probably ships as a "best-effort" indicator only, with explicit documentation of false-positive rate.
- *Why deferred:* Pcaptix calls these out individually as features but the combined value is moderate. Ship clipping detection as a Phase 11.3 sub-item if Phase 11 ships and bandwidth allows; treat noise and echo as research-grade and skip until someone has a compelling use case.

**PDF export of reports (including LLM responses)**
- *Trigger:* a real user asks for it — typically when sipnab analyses are being handed to customers or pulled into ticket systems that prefer PDF over Markdown.
- *Scope:* small. `typst-rs` (pure Rust, no LaTeX) or `printpdf` for the rendering. Take the existing Markdown report from `generate_call_report(format=Markdown)`, run it through the rendering pipeline. Add LLM-response capture from MCP/REST sessions when `--include-llm` is set. ~1–2 days when triggered.
- *Why deferred:* the existing Markdown report covers most needs — it pastes cleanly into tickets, GitHub, Confluence, Slack, etc. PDF is a "nice to have" that has not yet had a real user request. Ship reactively when one does.

### Categorically rejected (for the record)

These are listed so they don't have to be re-evaluated:

- **Raw SIP over NATS / Kafka / message buses** — non-standard wire format. HEP exists. Use HEP-over-NATS instead if the transport matters.
- **OTel as a packet source** — wrong protocol category. OTel carries traces, not packets. (OTel as an enrichment source is the candidate above.)
- **gRPC streaming of pcap** — combines two separately-rejected ideas.
- **Embedded SIP proxy / B2BUA mode** — sipnab observes, does not route. Already in v6 Non-Goals.
- **Audio codec decoding (G.711/G.729/Opus playback)** — already in v6 Non-Goals; the `audio` feature uses rodio for raw playback only, not decoding.
- **Built-in chat UI surface (Pcaptix-style "Explain with AI" panels)** — Phase 8's MCP gives this capability to any MCP client. Building a sipnab-specific chat UI duplicates work the agent-callable surface already covers more flexibly. (Per D22.)
- **OpenAI-only LLM integration** — MCP is provider-agnostic; tying to one LLM API would be a step backward. (Per D22.)
- **Qt or Electron desktop GUI** — Pcaptix occupies that niche. sipnab's TUI + WASM + CLI positioning is differentiated; abandoning it for a desktop GUI would be losing a fight that doesn't need to be fought. (Per D22.)
- **Licensed perceptual MOS algorithms (PESQ/POLQA)** — license costs and intrusive (reference-required) algorithms make these wrong for sipnab. NISQA (non-intrusive, MIT licensed) is the chosen path in Phase 11.2.

---

## Appendix — Mapping to Existing Code

For implementers picking this up, the bridge from each MCP tool to existing functions:

| MCP tool | Wraps |
|---|---|
| `list_dialogs` | `DialogStore::iter` (`src/sip/dialog_store.rs:194`) + `FilterExpr::matches_dialog` (`src/sip/dsl.rs:217`) + `expand_alias` (`src/sip/dsl.rs:138`) |
| `get_dialog` | `DialogStore::get` (`src/sip/dialog_store.rs:184`) + iterate `dialog.messages` + `output::json::message_to_json` |
| `get_dialog_report` | `output::generate_call_report` (`src/output/call_report.rs:34`) with `ReportFormat::Json/Markdown/Text` |
| `get_message` | `output::json::message_to_json` (`src/output/json.rs:150`) |
| `render_ladder` | `output::generate_call_report` with `ReportFormat::Markdown` (v0.4); rich SVG ladder deferred |
| `rtp_stats` | `StreamStore::iter` (`src/rtp/stream_store.rs:207`) + `rtp::diagnosis::diagnose_media` + `output::json::stream_to_json` |
| `search_messages` | Same iteration the `--filter` CLI path uses; `FilterExpr` covers most of it |
| `find_problems` | `list_dialogs` with each `expand_alias` result OR'd |
| `tail_dialogs` | `DialogStore::iter` filtered by `updated_at > cursor` |
| `security_findings` | `security::AlertEngine` history (extend with ring buffer) |
| `snapshot_pcap` | `capture::PcapWriter` + filter on captured packets |
| `stats` | Mirrors `GET /v1/stats` from `output::api::get_stats` (`src/output/api.rs:538`) |

| Phase 8 infra | Reuses |
|---|---|
| Bind address parsing | `output::api::parse_bind_addr` (`src/output/api.rs:171`) |
| Bearer auth | `output::api::check_auth` + `constant_time_eq` (`src/output/api.rs:279`, `:309`) |
| Rate limiting | `output::api::RateLimiter` (`src/output/api.rs:72`) |
| Shared store mirroring | `mirror_to_shared_stores` (`src/main.rs:2142`) |
| Server thread + tokio runtime | `start_api_server` pattern (`src/main.rs:2080`) |
| Privilege drop ordering | Existing capture-ready rendezvous + `privilege::drop_privileges` (`src/main.rs:387–442`) |
| WebSocket / SSE Router mounting | Extend `output::api::build_router` (`src/output/api.rs:150`) with new routes; reuse the existing `guard()` middleware |

| Phase 8.4 sink | Wraps |
|---|---|
| `ExecSink` | Existing `EventExecEngine::fire_dialog_event` / `fire_quality_event` (`src/output/event_exec.rs:88`, `:131`) — refactored to be one of N sinks rather than the only one |
| `McpSink` | New, publishes to MCP via rmcp `notifications/resources/updated` and custom `sipnab/dialog_event` |
| `WsSink` | New, broadcasts NDJSON over `axum::extract::ws::WebSocketUpgrade` |
| `SseSink` | New, broadcasts SSE frames over `axum::response::sse::Sse` |

| Phase 9 surface | Wraps / Extends |
|---|---|
| OpenAPI spec | `utoipa` annotations on existing `output::api` handlers — no new endpoints, only documentation |
| Swagger UI mount | New `/docs` route on the existing axum Router |
| OTel span on capture | `#[tracing::instrument]` on `capture::start_capture` (`src/capture/mod.rs`) |
| OTel span on parse | `#[tracing::instrument]` on `sip::parser::parse_sip` (`src/sip/parser.rs`) |
| OTel span on dialog state | `#[tracing::instrument]` on `DialogStore::process_message` (`src/sip/dialog_store.rs:99`) |
| OTel span on API handler | `#[tracing::instrument]` on each axum handler in `src/output/api.rs` |
| OTel span on MCP tool | `#[tracing::instrument]` on each `#[tool]` method in `src/mcp/server.rs` |
| OTel metrics export | New layer on existing Prometheus endpoint (`src/output/prometheus_server.rs`) plus OTLP exporter |
| `traceparent` header on incoming SIP | New parse step in `src/sip/parser.rs` to extract W3C trace context if header present |

| Phase 10 surface (deferred — preserved for un-deferral) | Wraps |
|---|---|
| `NatsSink` | New `EventSink` impl from Phase 8.4a, publishes via `async_nats::Client::publish` |
| Subject scheme | Derived from event type — no existing code to reuse, this is new |
| Connection lifecycle | `async_nats::ConnectOptions` with reconnect backoff |
| OTel correlation | When `otel` feature is on, attach `traceparent` NATS header from current span context |

| Phase 8.6 expansion (★) | Wraps |
|---|---|
| Quality timeline 680ms intervals | Existing `QualityInterval` in `src/rtp/stream.rs:37` — bump interval, add `status` field |
| OK/poor/uncertain trichotomy | New classification function alongside existing `estimate_mos` (`src/rtp/quality.rs:52`) |
| `.sipnab` project file | New module `src/project.rs`; reuses existing `output::json::dialog_to_json` for report content and `audio_export` for WAV files |
| `--open <foo.sipnab>` | New CLI dispatch path that bypasses the capture pipeline and rehydrates `DialogStore`/`StreamStore` from `report.json` |
| `--save-project <foo.sipnab>` | Wraps existing JSON output + `audio_export::extract_audio` (`src/rtp/audio_export.rs`) into a directory layout |

| Phase 8.7 surface (★) | Wraps |
|---|---|
| `codec_asymmetry` | Compares `RtpStream::codec` (`src/rtp/stream.rs:309 codec_from_pt`) across the two streams of a dialog |
| `ptime_asymmetry` | Inferred from RTP inter-arrival in `RtpStream::update` (`src/rtp/stream.rs:166`) or SDP `a=ptime:` parsed in `src/sip/sdp.rs` |
| `payload_asymmetry` | Compares payload types across streams; data already in `RtpStream` |
| `duration_asymmetry` | Compares stream start/end timestamps already tracked in `RtpStream` |
| `late_media` | Compares first RTP packet timestamp against dialog's 200 OK timestamp (already tracked in `dialog.timing`) |
| `one_sided_silence` | New analysis on decoded PCM samples from `audio_export`; energy threshold computation |
| All six tags | Extend existing `MediaDiagnosis` struct in `src/rtp/diagnosis.rs:14` (additive — backwards compatible JSON) |
| Six new diagnostic aliases | Extend `expand_alias` in `src/sip/dsl.rs:138` |
| TUI badges | Extend existing badge column in `src/tui/call_list.rs` |
| MCP `find_problems` integration | No code change — it consumes `expand_alias` already (Phase 8.3) |

| Phase 11 surface | Wraps / Extends |
|---|---|
| `extract_features` (11.1) | Pure function over `&[SipDialog]` and `&[RtpStream]`; no I/O |
| `regress` (11.1) | New use of `linfa-linear` — no existing equivalent |
| `--stats-analyze` CLI | New CLI mode that bypasses normal output, runs the analysis pipeline once on captured data |
| `analyze_features` MCP tool | Phase 8.3-style tool wrapping the above |
| Subnet partitioning (11.1) | Group `FeatureVector` by source-IP CIDR before regression — no existing code |
| `compute_nisqa` (11.2) | New module `src/rtp/perceptual_mos.rs` using `ort` (ONNX Runtime); consumes decoded PCM from existing `audio_export` |
| `RtpStream.perceptual_mos` field | Add to `src/rtp/stream.rs:65 RtpStream` (additive); compute lazily in stream finalization |
| `mos_divergence` diagnosis tag | Extend `MediaDiagnosis` struct (additive) |
| Model download (`--download-nisqa-model`) | New CLI subcommand, downloads to XDG path, SHA256 verifies |
| `--no-perceptual-mos` opt-out | New flag in `src/cli.rs` under a new `// ── Perceptual MOS ──` section |

The pattern is: **add nothing, wrap everything, bound the output.**
