# TUI Testing Guide

sipnab's TUI is tested at three levels.

## 1. Snapshot Tests (tests/tui_snapshot_test.rs)

Uses ratatui's `TestBackend` to render views to an in-memory buffer, then `insta` for snapshot comparison.

### Running
```bash
cargo test --features tui --test tui_snapshot_test
```

### Updating snapshots
When rendering changes intentionally:
```bash
cargo insta test --features tui --accept
git add tests/snapshots/
```

### Adding a new snapshot test
1. Create a test function that renders to `TestBackend`
2. Call `insta::assert_snapshot!(buffer_to_string(&terminal))`
3. Run `cargo insta test --accept` to create the initial snapshot
4. Commit the `.snap` file

## 2. State Machine Tests (tests/tui_state_test.rs)

Tests `App` state transitions without rendering. Uses `App::new_test()` and `App::handle_key()`.

```bash
cargo test --features tui --test tui_state_test
```

## 3. PTY End-to-End Tests (tests/tui_e2e_test.rs)

Spawns the real binary in a pseudo-terminal via `expectrl`. These are `#[ignore]` by default.

```bash
cargo test --features tui --test tui_e2e_test -- --ignored
```

These tests are slower (~2s each) and may be flaky in CI.
