# Lessons

## TUI: test rendering behavior, not just state transitions

**What happened:** Column visibility toggled correctly in `CallListState.visible_columns`, but `render_call_list` never consulted that field. Tests only asserted state changes (e.g., `assert!(column_selector_open)`), not that the renderer honored them.

**Rule:** When adding state that affects rendering, add a snapshot test with populated data that exercises the visual change. State machine tests prove the flag flips; snapshot tests prove the renderer reads it.

**Applies to:** Any TUI feature where state drives visual output -- column visibility, timestamp modes, color modes, filter display, etc.

## Feature flags: stub features must be documented or removed

**What happened:** `tls-wolfssl`, `tls-openssl`, and `grpc` feature flags exist in Cargo.toml and pull dependencies, but contain zero implementation. wolfSSL and OpenSSL just alias `tls` (ring backend). gRPC pulls tonic/prost but has no proto files or service code. A user enabling these flags gets no additional functionality.

**Rule:** Feature flags must either (a) gate real code or (b) be removed. If a feature is planned but not implemented, document it as such in README/CHANGELOG and don't ship the flag. Stub flags waste compile time and mislead users.

**Applies to:** Any Cargo.toml feature that gates optional functionality.

## Config sections: don't parse what you don't use

**What happened:** `config.rs` parses `theme` and `keybindings` TOML sections correctly, but the TUI hardcodes colors and key mappings. The config values are loaded then ignored.

**Rule:** If a config section is parsed, it must be wired to behavior. If wiring is deferred, add a warning log ("theme config loaded but not yet applied") so users aren't confused when their config has no effect.

**Applies to:** Any config-driven behavior — validate the full loop from parse → apply → visible effect.

## Documentation: audit periodically against the codebase, not "as you go"

**What happened (2026-05-05):** A multi-axis audit of every doc surface against current source surfaced 4 BLOCKING and ~17 MAJOR drifts that had accumulated since 0.3.1 (April):

- `config.md` `visible_columns` listed 4 invalid column names — users copying the example would get configs that match nothing.
- `cli.md` + `troubleshooting.md` jq recipes used `.status` instead of `.status_code` — silently emitted nulls.
- `docs/install.md` and `CLAUDE.md` feature-flag tables were stale (default = `[]`, listed phantom `tls-wolfssl`/`tls-openssl`/`grpc`, missed `mcp`/`mcp-http`/`audio`/`native`).
- `api.md` listed phantom Prometheus metric names (`sipnab_rtp_mos_histogram` etc.) that never existed.
- `mcp.md` referenced a nonexistent `--cli-print` flag.
- `filter-dsl.md` claimed 24 fields when source had 30; missing all 5 Phase 8.7 asymmetry aliases (`codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`).
- `CHANGELOG.md` `[Unreleased]` was missing 12+ user-visible commits; release dates were wrong (0.3.1 dated *before* 0.3.0).
- `CLAUDE.md` module layout omitted entire directories (`src/mcp/`, audio modules under `rtp/`, `src/crypto.rs`, `src/privilege.rs`, `src/process_isolation.rs`, `src/signals.rs`, `src/wasm.rs`) and named one (`src/sip/correlation.rs`) that doesn't exist.
- `implementation-plan-v6.md` D14 still described a multi-backend crypto plan that was silently dropped (only `ring`/`rustls` ever shipped).

These drifted because each individual change was small enough not to think "should I update the docs?" — but the cumulative drift was substantial.

**Rule:** Run a structured doc audit on a cadence (every release boundary, or every ~10 user-visible commits). The recipe that worked:

1. Dispatch parallel agents per doc surface (website docs / repo dev docs / planning docs) — each gets the source-of-truth files (`Cargo.toml`, `src/cli.rs`, `src/mcp/server.rs`, `src/output/prometheus.rs`, `src/sip/dsl.rs`, recent `git log`) and a structured-findings output format.
2. Spot-check the high-impact claims before mass-editing (the agents are not infallible — one of them invented a non-existent rate-limit-claim issue this round; another miscounted DSL fields).
3. Triage by severity: BLOCKING (user follows doc → wrong outcome) → MAJOR (wrong feature listed) → MINOR (count drift, internal inconsistency) and fix in that order.

**What to grep for as a cheap regression check:**

```bash
# phantom feature flags that haven't existed since 0.3.x
grep -rnE "tls-wolfssl|tls-openssl|\bgrpc\b" docs/ website/content/ README.md CLAUDE.md

# stale field counts (current is 30; let the count drift past 25 = audit time)
grep -rnE "(2[0-9]|30) (fields|addressable)" docs/ website/content/ website/templates/

# claimed Prometheus metrics vs what `src/output/prometheus.rs` emits
diff <(grep -oE "sipnab_[a-z_]+" website/content/docs/api.md | sort -u) \
     <(grep -oE '"sipnab_[a-z_]+"' src/output/prometheus.rs | tr -d '"' | sort -u)

# phantom CLI flags in docs
grep -oE -- "--[a-z-]+" website/content/docs/cli.md docs/cli-reference.md \
  | sort -u | while read f; do grep -qF "$f" src/cli.rs || echo "stale: $f"; done

# CHANGELOG `[Unreleased]` empty even though commits landed
git log --oneline "v$(awk -F'"' '/^version/ {print $2}' Cargo.toml)..HEAD" -- ':!CHANGELOG.md' | head
```

**Applies to:** Every release-candidate moment, every doc-only commit cycle, every "I keep meaning to update those docs" moment that lasts more than a month.
