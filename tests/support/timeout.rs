// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Included textually with `include!`, not as a module: `support/server.rs` and
// `support/mcp.rs` are themselves pulled in with `#[path]` by several test
// binaries, so a nested module path would resolve differently depending on the
// including file. `include!` is relative to the current file and therefore
// unambiguous from all of them.

/// A test deadline in seconds, scaled by `SIPNAB_TEST_TIMEOUT_SCALE`.
///
/// Every wall-clock deadline in the integration suites is a bet on how fast the
/// binary starts and answers. Under ThreadSanitizer that bet is wrong by
/// roughly an order of magnitude — instrumented code against an instrumented
/// `std` runs several times slower — so the deadlines are scaled rather than
/// raced against.
///
/// The history is worth stating accurately, because this file used to state it
/// wrongly. The seven `did not report a listening address` failures that first
/// motivated this scale were **not** slowness: the spawned servers were being
/// aborted by TSan's `halt_on_error`, and `support/server.rs` reported a
/// deadline it had never waited out. Scaling remains right for instrumented
/// builds — it simply was not the fix for that run, and reading it as the fix
/// cost a full cycle of investigation aimed at runner speed.
///
/// It is an environment variable rather than a TSan-specific constant because
/// the same slowdown appears under `cargo-llvm-cov` and on a loaded runner. An
/// unset, empty, zero or unparsable value means 1 — a scale that silently read
/// as zero would turn every deadline into an instant timeout, which is the
/// same class of bug in the opposite direction.
#[allow(dead_code)]
fn test_timeout(secs: u64) -> std::time::Duration {
    let scale = std::env::var("SIPNAB_TEST_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1);
    std::time::Duration::from_secs(secs.saturating_mul(scale))
}
