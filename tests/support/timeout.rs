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
/// `std` runs several times slower — and the 15-second wait for the API to
/// report its bound port expired before the server had finished binding. The
/// first sanitizer run came back red with seven `did not report a listening
/// address` failures and **zero races**.
///
/// That is the failure mode worth naming: a sanitizer whose red means "the
/// runner was slow" teaches everyone to ignore it, and then the run where it
/// means "there is a data race" is ignored too. The scale exists so the job's
/// red keeps meaning what the job is for.
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
