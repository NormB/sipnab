# TUI testing guide

sipnab tests its TUI at three levels.

## Snapshot tests (tests/tui_snapshot_test.rs)

These tests use ratatui's `TestBackend` to render views to an in-memory buffer. Then they use `insta` for snapshot comparison.

### Running
```bash
cargo test --features tui --test tui_snapshot_test
```

### Updating snapshots
Use this when rendering changes intentionally.

- `--accept` rewrites the `.snap` files in place.
- Stage them in the same commit.
  - That is what keeps CI comparing against the new rendering.
```bash
# Run all of these, in order.
cargo insta test --features tui --accept
git add tests/snapshots/
```

### Adding a new snapshot test
- Create a test function that renders to `TestBackend`
- Call `insta::assert_snapshot!(buffer_to_string(&terminal))`
- Run `cargo insta test --accept` to create the initial snapshot
- Commit the `.snap` file

## State machine tests (tests/tui_state_test.rs)

These tests check `App` state transitions without rendering. They use `App::new_test()` and `App::handle_key()`.

```bash
cargo test --features tui --test tui_state_test
```

## PTY end-to-end tests (tests/tui_e2e_test.rs)

These tests drive the real binary inside a detached `tmux` session. They do not use a bare PTY.

- sipnab's TUI queries the terminal at startup.
  - crossterm emits `ESC[6n` to read the cursor position.
- A bare pseudo-terminal has no emulator behind it to answer.
  - So the TUI aborts with `cursor position could not be read`.
- tmux *is* a terminal emulator. It does three things:
  - It answers the query.
  - It provides a real window size.
  - It lets the test send keys and snapshot the screen with `capture-pane`.
- Each test session runs on its own tmux server (`tmux -L <session>`), and
  removes that server's socket when it ends.
  - A tmux server exits when its last session ends. On one shared server, a
    test starting a session at that moment failed with `tmux new-session failed`.
- These tests are `#[ignore]` by default.
- They need `tmux` on `PATH`.

```bash
cargo test --features tui --test tui_e2e_test -- --ignored
```

These tests are slower (~2s each). They may be flaky in CI.

## Bare-PTY stop tests (tests/tui_lost_terminal_test.rs)

These tests check how the TUI stops: on SIGTERM, SIGINT and SIGHUP, and when
its terminal goes away. They run the real binary on a pseudo-terminal the test
owns, without tmux, because a hang-up is something the test does to that
terminal.

### Prerequisites
- Linux. The pty set-up uses Linux's `openpty` and `TIOCSCTTY` behavior.
- A build with the `tui` feature. The tests are not `#[ignore]`d, so the
  suite runs them.

### Running the stop tests
```bash
cargo test --features tui --test tui_lost_terminal_test
```

### How a test reads the terminal
- A reader thread plays the terminal. It collects what sipnab writes and
  answers the cursor-position query (`ESC[6n`) that crossterm sends at startup.
- `wait_until_drawn` waits for the call list (`INVITE`) on the terminal. Only
  then does a test send a signal or hang the terminal up, so sipnab has
  installed its signal handlers and drawn the first frame.
- `wait_for_exit` returns the exit status once the child has ended AND the
  reader has read everything the child wrote. The reader ends when a read of
  the pty's master side fails with `EIO`, which Linux returns once no process
  holds the slave side open and no written byte remains.
  - Before this, `wait_for_exit` returned at the exit alone. The reader runs
    on its own schedule, so on a loaded host the terminal restore
    (`ESC[?1049l`) could still be unread when the test asked for it, and
    `sigterm_stops_a_tui_and_restores_the_terminal` could fail although
    sipnab had written the restore.
- `stall_reader` stops the reader for a set time and returns once it has
  stopped. The `*_when_the_reader_lags_the_exit` tests use it to put the exit
  before the reader's next read, which is the order a loaded host can produce.
- `spawn_command` runs any program on the same kind of pty, for the tests of
  the reader itself (`the_last_bytes_before_an_exit_are_read` and the two
  after it).

### How to verify
All tests pass, and the run takes a few seconds:
`input_crossterm_leaves_unread_does_not_make_the_tui_spin` measures CPU over
4 s, and the stalled-reader tests each wait out a 3 s stall.

### Troubleshooting
- `the terminal was still open after sipnab exited`: a process other than
  the child still holds the pty's slave side, so the reader never reads
  `EIO`. A test that spawns its own processes must not hand them the pty.
- `sipnab did not draw the call list within 60 s`: the TUI did not start.
  Run `sipnab -I sip_call.pcap` in `tests/fixtures` in a terminal to see
  what it shows instead.
- `the pty reader thread did not stall within 10 s`: the reader thread is
  blocked outside its loop. It holds no lock across a read, so this points
  at a change to `serve_terminal`.
