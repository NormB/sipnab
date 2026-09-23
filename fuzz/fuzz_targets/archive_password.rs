// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the archive and password layer: ZIP (none, ZipCrypto, AES), 7z (none,
//! AES-256, encrypted headers), gzip and tar, nested, with one password taken
//! from the input. An archive named with `-I`, opened by the TUI, by MCP
//! `open_capture` or by the REST compare route is attacker-shaped input, and
//! the walk, the decryptors and the trial-and-rollback logic must return on
//! any bytes: never panic, never spin. The body is
//! `sipnab::capture::archive::fuzz_one_archive`, which
//! `tests/archive_fuzz_replay_test.rs` also drives on every `cargo test`.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sipnab::capture::archive::fuzz_one_archive(data);
});
