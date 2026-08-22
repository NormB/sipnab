# Test architecture

Fifty integration-test binaries under [`tests/`](../../tests), plus unit tests
inside `src/`, plus doctests. The exact total is not repeated here on purpose —
the homepage stat card carries it and a pre-commit gate holds it, so
any number written on this page would be wrong within a week.

What follows is the map: what each tier asserts, how to regenerate its
artifacts, and — most importantly — the roster of *gate tests* that fail you
for reasons that have nothing to do with the code you were writing.

## Tiers

| Tier | Files | Asserts |
|---|---|---|
| **CLI surface** | [`cli_test`](../../tests/cli_test.rs), [`cli_options_test`](../../tests/cli_options_test.rs), [`cli_help_test`](../../tests/cli_help_test.rs), [`cli_defaults_test`](../../tests/cli_defaults_test.rs), [`cli_flag_behavior_test`](../../tests/cli_flag_behavior_test.rs) | Parsing, the default value of every parameter, `--help` grouping across ~160 flags, and behavior for flags that were once untested. |
| **CLI golden** | [`cli_goldens`](../../tests/cli_goldens.rs) | `trycmd` goldens under [`tests/cli/`](../../tests/cli) — exact stdout/stderr for a command line. |
| **Integration** | [`integration_test`](../../tests/integration_test.rs), [`capture_test`](../../tests/capture_test.rs), [`rtp_integration_test`](../../tests/rtp_integration_test.rs), [`pipeline_test`](../../tests/pipeline_test.rs), [`parse_path_test`](../../tests/parse_path_test.rs), [`bootstrap_test`](../../tests/bootstrap_test.rs), [`app_servers_test`](../../tests/app_servers_test.rs), [`config_test`](../../tests/config_test.rs) | Capture-to-output pipeline, and the library facades WS2 extracted from `main.rs` — bootstrap planning is a pure `Cli + Config → RunPlan` function precisely so these tests can reach it. `config_test` covers the step before planning: config discovery (`-f`, `SIPNAB_CONFIG`, `--no-config`, unknown-key warnings, the missing-file error) driven through the real binary's `--dump-config`. |
| **TUI** | [`tui_snapshot_test`](../../tests/tui_snapshot_test.rs), [`tui_state_test`](../../tests/tui_state_test.rs), [`tui_e2e_test`](../../tests/tui_e2e_test.rs) | Rendered buffers via ratatui's `TestBackend` + `insta`; state-machine transitions; and end-to-end drives of the real binary inside `tmux`. See [TUI testing](tui-testing.md). |
| **Servers** | [`api_test`](../../tests/api_test.rs), [`api_token_test`](../../tests/api_token_test.rs), [`mcp_stdio_test`](../../tests/mcp_stdio_test.rs), [`mcp_http_test`](../../tests/mcp_http_test.rs), [`mcp_token_test`](../../tests/mcp_token_test.rs), [`mcp_token_rotation_test`](../../tests/mcp_token_rotation_test.rs), [`metrics_test`](../../tests/metrics_test.rs), [`hep_test`](../../tests/hep_test.rs) | REST, MCP (stdio and HTTP), signed-token auth and rotation, Prometheus scrapes, HEP ingestion — all end to end against a spawned process. |
| **Security** | [`security_test`](../../tests/security_test.rs), [`privilege_drop_test`](../../tests/privilege_drop_test.rs), [`resource_bounds_test`](../../tests/resource_bounds_test.rs), [`crash_test`](../../tests/crash_test.rs) | Audit regressions, the never-continue-as-root guarantee, attacker-keyed map caps, and crash-report handling with the real binary. |
| **Property & fuzz** | [`property_test`](../../tests/property_test.rs), [`smoke_fuzz_test`](../../tests/smoke_fuzz_test.rs), [`fuzz_corpus_replay`](../../tests/fuzz_corpus_replay.rs) | `proptest` invariants; the always-on stable-toolchain fuzz floor; and — despite its name — a deterministic sweep over an adversarial seed set defined *in the file itself*, not a replay of [`fuzz/corpus/`](../../fuzz/corpus/) (it opens no files). |
| **Contract** | [`json_schema_test`](../../tests/json_schema_test.rs), [`summary_consistency_test`](../../tests/summary_consistency_test.rs), [`output_behavior_test`](../../tests/output_behavior_test.rs), [`error_types_test`](../../tests/error_types_test.rs), [`api_guidelines_test`](../../tests/api_guidelines_test.rs), [`wasm_exports_test`](../../tests/wasm_exports_test.rs) | The shapes other people's code depends on: JSON schemas, cross-surface summary agreement, machine-readable output flags, typed errors, `#[non_exhaustive]` on growth-prone enums, WASM export list. |
| **Docs enforcement** | [`docs_drift_test`](../../tests/docs_drift_test.rs), [`dev_docs_drift_test`](../../tests/dev_docs_drift_test.rs), [`link_integrity_test`](../../tests/link_integrity_test.rs), [`doc_example_coverage_test`](../../tests/doc_example_coverage_test.rs), [`config_examples_test`](../../tests/config_examples_test.rs), [`site_journey_test`](../../tests/site_journey_test.rs), [`mockup_alignment_test`](../../tests/mockup_alignment_test.rs) | See the gate roster below. |
| **Governance** | [`flag_coverage_test`](../../tests/flag_coverage_test.rs), [`keybinding_drift_test`](../../tests/keybinding_drift_test.rs), [`feature_gate_test`](../../tests/feature_gate_test.rs), [`config_wiring_test`](../../tests/config_wiring_test.rs) | Rules about *how the project grows*, not about a specific behavior. |
| **Meta** | [`support_selftest`](../../tests/support_selftest.rs) | The shared test helpers have their own tests. |

## [`tests/support/`](../../tests/support/)

Files in a subdirectory of `tests/` are **not** compiled as their own test
binaries, so an explicit path attribute pulls shared helpers in:

```rust
#[path = "support/run.rs"]
mod run;
```

That idiom is why the same module appears in several test files
with no `mod.rs` chain — each test binary compiles its own copy.

| Helper | Provides |
|---|---|
| [`mod.rs`](../../tests/support/mod.rs) | Shared normalization (`normalize()`) used to compare output across platforms; self-tested by `support_selftest`. |
| [`run.rs`](../../tests/support/run.rs) | The canonical binary-spawn helper for CLI/output/config integration tests — one place that knows how to find and invoke the built binary. |
| [`server.rs`](../../tests/support/server.rs) | REST API spawn harness: start the server on an ephemeral port, wait for readiness, tear down. |
| [`mcp.rs`](../../tests/support/mcp.rs) | The same for HTTP MCP, including the JSON-RPC framing. |
| [`schema.rs`](../../tests/support/schema.rs) | JSON-Schema validation against [`tests/schemas/`](../../tests/schemas). |
| [`tui_fixtures.rs`](../../tests/support/tui_fixtures.rs) | SIP fixture builders shared by the TUI snapshot and state tests. |
| [`fuzz.rs`](../../tests/support/fuzz.rs) | A deterministic xorshift PRNG shared by the stable-toolchain fuzzers, so a failure reproduces from its seed. |

## Fixtures and corpora

Every command below ran against the current tree and left it unchanged —
that is the point of documenting them: if one produces a diff, something has
drifted.

| Artifact | Regenerate with |
|---|---|
| [`tests/fixtures/`](../../tests/fixtures) — synthetic pcaps | `cargo run --features native --bin gen_fixture` |
| [`tests/snapshots/`](../../tests/snapshots) — TUI buffers | `cargo insta test --features tui --accept` (needs `cargo install cargo-insta`) |
| [`tests/cli/`](../../tests/cli) — trycmd goldens | `TRYCMD=overwrite cargo test --features full --test cli_goldens` |
| [`tests/schemas/`](../../tests/schemas) — JSON Schemas | Hand-maintained; `json_schema_test` validates output against them. |
| [`tests/pcap-samples/`](../../tests/pcap-samples) — capture fixtures | Thirteen are synthetic: `python3 tests/gen-pcap-samples.py` writes ten and `python3 tests/gen-link-type-samples.py` writes the three link-layer framings (DLT_LOOP, PPPoE inside Linux cooked capture v1 and v2); each script in check mode reports any of its own that have drifted from it. Nothing regenerates the rest; they stay as checked in. |
| [`tests/install-sh/`](../../tests/install-sh) — installer cases | Hand-maintained; exercised by the `install-sh` CI job. |
| [`fuzz/corpus/`](../../fuzz/corpus) — fuzz seeds | Grown by `cargo fuzz run` (nightly). Note nothing on the stable toolchain reads this directory: `fuzz_corpus_replay` drives its own in-file seed set. To make a reproducer run in every `cargo test`, add it to `smoke_fuzz_test` as well. |

Accepting a snapshot or overwriting a golden is a **decision**, not a fix. Read
the diff first: these files are the record of what the tool promised its users.

## The gate-test roster

These fail on changes you thought had nothing to do with them. Each one exists because
the thing it guards silently rotted at least once.

| Gate | Trips when |
|---|---|
| [`docs_drift_test`](../../tests/docs_drift_test.rs) | A `--flag` named in `README.md`, `../architecture.md` or the website does not exist in the CLI; a version marker in the docs or man page disagrees with `Cargo.toml`; the README feature table misses a Cargo feature; a `[theme]` slot in `ThemeConfig` has no documentation, or the slot count quoted in either config reference is wrong. Also the benchmark reproducibility contract: the `bench/` harness the benchmarks page tells readers to run must exist and be executable, [`bench/carrier.py`](../../bench/carrier.py) must still produce the corpus composition the page quotes (checked at 1/100 scale), and both doc trees must name the same measured artifact and date. |
| [`dev_docs_drift_test`](../../tests/dev_docs_drift_test.rs) | A page under `docs/internals/` links to a path that no longer exists, names a `fn` that no longer exists, uses an absolute GitHub URL instead of a relative one, is not registered in `build-wiki.py`, or breaks a mermaid convention. It also builds the wiki and fails if any relative link survives into the output — the wiki is flat and has no repo tree, so such a link publishes dead. That check runs the generator rather than reading it: the version that only asserted `CODE_LINK_RE` appeared in the script passed while `](../bench/)` was shipping broken. |
| [`link_integrity_test`](../../tests/link_integrity_test.rs) | Any relative link or heading anchor in either doc tree does not resolve; Zola content uses a plain relative `.md` link that would render as a dead URL. On the wiki-source side the scan is the top-level `docs/*.md` plus `docs/internals/` — `docs/design/`, `docs/research/` and `docs/superpowers/` are planning material outside the published journey and are deliberately not walked, though a link *into* them from a scanned page still has to resolve. A third scope covers the root community files (`README.md`, `SUPPORT.md`, `MAINTAINERS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`), which neither doc tree walks — these are what GitHub renders in the sidebar, so a rename that broke their cross-references used to go unnoticed. |
| [`doc_example_coverage_test`](../../tests/doc_example_coverage_test.rs) | A user-facing CLI flag appears in fewer than two documented examples. A ratchet — the exemption list may only shrink. |
| [`flag_coverage_test`](../../tests/flag_coverage_test.rs) | A new long flag ships with no test referencing it. Also a ratchet: adding a test for a grandfathered flag fails until you remove it from the baseline list. |
| [`keybinding_drift_test`](../../tests/keybinding_drift_test.rs) | A controller handles a key that the F1 help never mentions. |
| [`config_wiring_test`](../../tests/config_wiring_test.rs) | A config key exists but is never read, or a CLI flag has no config fallback where its peers do. |
| [`feature_gate_test`](../../tests/feature_gate_test.rs) | A flag whose subsystem is not compiled in fails late or silently instead of fast and clearly. |
| [`api_guidelines_test`](../../tests/api_guidelines_test.rs) | A growth-prone public enum loses `#[non_exhaustive]`, or a shared store stops being `Debug`. |
| [`summary_consistency_test`](../../tests/summary_consistency_test.rs) | Two serializing surfaces disagree about a dialog or stream field. |
| [`wasm_exports_test`](../../tests/wasm_exports_test.rs) | The WASM binding loses an export the browser analyzer calls. |
| [`site_journey_test`](../../tests/site_journey_test.rs) / [`mockup_alignment_test`](../../tests/mockup_alignment_test.rs) | A website journey breaks, or a terminal mockup on the site drifts from real output. Also the homepage's advertised numbers: the binary-size ceiling, the glibc floor, the throughput tiles (which must quote a figure that appears on the benchmarks page they link to), and the two automated-test counts, which must agree with each other and — via `quality.yml` — with the measured total. It also holds the homepage's four MCP examples to the files [`gen-mcp-examples.sh`](../../demos/gen-mcp-examples.sh) generated, and holds each of those to the claim the surrounding copy makes about it. That covers the second half of `live binary -> website/data/mcp-examples/*.json -> index.html`; `demos/gen-mcp-examples.sh --check` covers the first and needs a built binary, so CI cannot run it. |
| [`config_examples_test`](../../tests/config_examples_test.rs) | A config sample in the docs no longer parses. |
| [`support_selftest`](../../tests/support_selftest.rs) | The shared normalization helper changes behavior under the tests that depend on it. |

The rule for all of them: **the gate is not the problem**. If
`flag_coverage_test` fails, the flag needs a test. If `dev_docs_drift_test`
fails, a page now lies. Adding an exemption is the last resort, and every
exemption list in this repo works as a ratchet so it cannot quietly grow.

## The development loop

**Logging.** `SIPNAB_LOG` is a `tracing` `EnvFilter`, so it takes levels and
per-module directives (`SIPNAB_LOG=debug`, `SIPNAB_LOG=sipnab::rtp=trace`).
In TUI mode sipnab suppresses logging unless `SIPNAB_LOG` says otherwise — the
alternative is log lines painting over the interface. `-q` lowers the default
in CLI mode. Configured by [`init_logging()`](../../src/app/bootstrap.rs).

**Benches.** `cargo bench --profile profiling`. Plain `cargo bench` *cannot
build*: the `cdylib` crate type needed for the WASM build forces
`panic = "abort"` into the lib unit while bench units build with
unwind, so shared dependencies get built twice with incompatible panic
strategies and fail to unify. The `profiling` profile is release codegen with
`panic = "unwind"` and debug symbols kept, which is also what callgrind wants.
Baselines live in [`benches/BASELINES.md`](../../benches/BASELINES.md).

**nextest.** [`.config/nextest.toml`](../../.config/nextest.toml) defines three profiles: `default` (no retries, 30s slow timeout), `ci` (no retries, no
fail-fast, immediate-final output) and `e2e` (2 retries, 60s timeout) for the
timing-sensitive tmux tests. Worth knowing: **no workflow currently invokes
nextest** — CI runs plain `cargo test`. The config is there for local use and
for the day the e2e shim goes away.

**The docker lab.** [`harness/`](../../harness) is a docker-compose stack —
OpenSIPS, rtpengine, SIPp — for generating real traffic. `make up` in that
directory builds and starts it, and `make down` tears it down.

**WASM.** Two pre-commit gates cover the browser analyzer: one checks that
[`website/static/wasm/sipnab.js`](../../website/static/wasm/sipnab.js) still exports
every function the site calls.

A second gate once demanded a freshly built bundle alongside any staged
[`src/wasm.rs`](../../src/wasm.rs). It no longer exists, nor does the binary it guarded: the published
analyzer went eleven releases stale while that gate stayed green, because
[`src/wasm.rs`](../../src/wasm.rs) had no commits in the window — the interface held still while the
implementation behind it moved. The Pages workflow builds the bundle at deploy
time now, so the build produces what ships rather than the tree carrying it, and it cannot go stale.

**Feature matrices.** A green `cargo test --features full` is not proof: CI
also builds reduced feature sets, and code behind `#[cfg(not(feature = ...))]`
is invisible to the full build. Before pushing, `cargo clippy --workspace --all-features
--all-targets -- -D warnings` and the `fuzz` workspace check are what the
pre-push hook runs for exactly this reason.
