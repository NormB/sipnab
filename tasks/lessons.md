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
