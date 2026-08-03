// SPDX-License-Identifier: MIT OR Apache-2.0

//! The corpus gate, and the one line that says when it did not run.
//!
//! Every corpus-backed test binary reads `SIPNAB_CORPUS` and returns early
//! when it is unset. That is correct — the validation corpus is real captured
//! traffic that must not leave the machine it was taken on, so CI cannot set
//! the variable and a contributor without the captures must still get a green
//! suite.
//!
//! What was not correct is that the skip was **invisible**. Each file printed
//! `eprintln!("SIPNAB_CORPUS not set — skipping")` from inside a test body,
//! and libtest captures `print!`/`eprintln!` per test and throws the buffer
//! away when the test passes. So the notice existed, compiled, and reached
//! nobody. Nine binaries and 25 tests reported `ok` while proving nothing, and
//! `documented_fields_select_the_right_rows_on_real_captures` sat red against
//! every real capture — exit code 2, a case row naming a filter field that had
//! been withdrawn from the DSL — for as long as the field had been gone. It
//! was found by a human running the corpus suite by hand.
//!
//! Two properties follow, and both are gated in `corpus_skip_notice_test`:
//!
//! 1. **The notice must escape libtest's capture.** [`announce_skipped`]
//!    writes to [`std::io::stderr`] directly rather than through `eprintln!`,
//!    because the capture is installed on the `print!` machinery only. A
//!    child-process test in `corpus_skip_notice_test` runs a probe *without*
//!    `--nocapture` and asserts the line still arrives, so a well-meaning
//!    rewrite back to `eprintln!` fails rather than going quiet again.
//! 2. **One line per binary, not per test.** A [`Once`] collapses the
//!    per-test calls. A full `cargo test` crosses a dozen corpus binaries; at
//!    one line each that is a readable notice, and at one line per *test* it
//!    is a wall nobody reads — which is the same failure in a louder font.
//!
//! The skip is deliberately NOT a failure. Making the absent corpus red would
//! push the next contributor to delete the gate, and a deleted gate is exactly
//! what this module exists to prevent.
#![allow(dead_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Once;

/// The environment variable naming the real-capture corpus root.
pub const ENV_VAR: &str = "SIPNAB_CORPUS";

/// The corpus root, or `None` when [`ENV_VAR`] is unset — announcing the skip
/// on the way out so a green run cannot be mistaken for a validated one.
///
/// # Returns
/// `Some(root)` when `SIPNAB_CORPUS` names a path; `None` otherwise.
///
/// # Side effects
/// On the `None` path, writes [`notice_line`] to stderr once per test binary.
pub fn root() -> Option<PathBuf> {
    match std::env::var(ENV_VAR) {
        Ok(dir) => Some(PathBuf::from(dir)),
        Err(_) => {
            announce_skipped();
            None
        }
    }
}

/// Write the "real-capture gates did not run" line to stderr, at most once per
/// process.
///
/// # Side effects
/// Writes one line to the process's real stderr, bypassing libtest's output
/// capture. Deliberately ignores a write error: a test binary whose stderr is
/// closed has bigger problems than a missing notice, and panicking here would
/// convert a *skip* into a failure.
pub fn announce_skipped() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // NOT eprintln!. libtest replaces the print machinery's sink per test
        // thread and discards the buffer for a test that passes, which is how
        // the previous notice managed to be emitted and never seen. A direct
        // handle write is not part of that machinery.
        let line = notice_line(env!("CARGO_CRATE_NAME"));
        let _ = writeln!(std::io::stderr(), "{line}");
    });
}

/// The notice, as a string, so its wording can be asserted without spawning
/// anything.
///
/// # Arguments
/// * `binary` — the test binary the gates live in, so a dozen of these lines
///   in one `cargo test` run each say which suite went unproven.
#[must_use]
pub fn notice_line(binary: &str) -> String {
    format!(
        "NOTICE: {ENV_VAR} is unset — the real-capture gates in `{binary}` did NOT run. \
         This suite being green is not full validation; set {ENV_VAR}=<dir of captures> to run them."
    )
}

/// The fragment every notice carries, for tests and for `grep`.
pub const NOTICE_MARKER: &str = "did NOT run";
