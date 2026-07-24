// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared deterministic PRNG for the always-on stable-toolchain fuzzers.
//!
//! Both `fuzz_corpus_replay.rs` and `smoke_fuzz_test.rs` drive the wire
//! parsers with a reproducible mutation sweep. They previously each defined
//! their own copy of this xorshift64 generator; the generator is the one piece
//! that is genuinely identical between them, so it lives here and both include
//! it with `#[path = "support/fuzz.rs"] mod fuzz;`.
//!
//! The two `mutate()` helpers are intentionally NOT shared: they are different
//! mutation strategies (corpus-replay uses a 4-op sweep, smoke a richer 6-op
//! sweep with a size cap), so unifying them would change the byte stream each
//! test produces and break corpus reproducibility. Only the PRNG is shared.
//!
//! Reproducibility contract: for a given seed the `next_u64` sequence — and
//! therefore every `byte()`/`below()` derived from it — is fixed across runs,
//! machines, and toolchains, so a failing input is always replayable.
//!
//! This file lives in a `tests/` subdirectory, so cargo does not compile it as
//! its own test binary. `#![allow(dead_code)]` because each consumer uses only
//! a subset of the API (corpus-replay never calls `below`, for example).
#![allow(dead_code)]

/// Tiny deterministic xorshift64 PRNG — no `rand` dependency, reproducible
/// across runs so a fuzz failure is always replayable from its seed.
pub struct Rng(u64);

impl Rng {
    /// Seeds the PRNG; forces the low bit so the xorshift state is never zero
    /// (an all-zero state is a fixed point that only ever yields zero).
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    /// Advances the xorshift state and returns the next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Returns the low byte of the next PRNG value.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /// Returns a value in `0..n` (0 when `n` is 0).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}
