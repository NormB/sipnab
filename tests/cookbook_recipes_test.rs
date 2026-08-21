// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every command the cookbook tells a reader to paste still works.
//!
//! `docs/examples.md` is the one page that instructs rather than describes.
//! Everything else can go stale and still read plausibly; a cookbook command
//! that names a flag which no longer exists fails at a shell, in front of
//! someone who trusted the page. Prose rots quietly. Commands rot loudly, and
//! only for the reader.
//!
//! The checker in `scripts/check-cookbook.py` puts every sipnab command in the
//! page into one of three buckets and reports all three:
//!
//! - **executed** — the command reads a capture and exits, so the placeholder
//!   path is replaced with a real fixture and the command is RUN. Proves the
//!   flags parse, the run completes, and the status is zero.
//! - **flag-checked** — the command needs a live interface, root, or a socket
//!   to serve on. It is not run; every long flag it names must exist in
//!   `sipnab --help`. Weaker, but it catches the failure that actually happens
//!   to a cookbook.
//! - **UNCOVERED** — neither. Counted and printed, never skipped in silence. A
//!   checker that ignores what it cannot handle reports a clean page by not
//!   looking at it, which is the shape [[feedback_empty_output_is_not_evidence]]
//!   warns about and the reason RDR2 is open.
//!
//! Gated on the `full` feature set because the bucket a command lands in
//! depends on it: `--help` from a binary built without `hep` does not list
//! `--hep-listen`, so recipe 26 would "fail" on a build that was never asked
//! to carry it.
#![cfg(all(
    feature = "native",
    feature = "tls",
    feature = "hep",
    feature = "mcp",
    feature = "api",
    feature = "metrics",
    feature = "plugins",
))]

use std::path::Path;
use std::process::Command;

/// Run the cookbook checker against the binary this test run just built.
///
/// `CARGO_BIN_EXE_sipnab` is the binary cargo built for THIS test invocation,
/// not whatever happens to be sitting in `target/debug`. A stale binary is how
/// a check passes against a version that no longer exists — the same trap as
/// a test that reads a build artefact it did not produce.
#[test]
fn every_cookbook_command_still_works() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/check-cookbook.py");
    assert!(script.exists(), "missing {}", script.display());

    let out = Command::new("python3")
        .arg(&script)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(repo)
        .output()
        .expect("run scripts/check-cookbook.py (python3 must be on PATH)");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "a cookbook command no longer works.\n\
         Reproduce: python3 scripts/check-cookbook.py --verbose\n\n\
         {stdout}\n{stderr}"
    );

    // A checker that silently stopped finding commands would pass every
    // assertion above by examining nothing. Anchor on the page actually
    // having been read.
    let executed = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("executed against a fixture :"))
        .and_then(|n| n.trim().parse::<u32>().ok())
        .unwrap_or(0);
    assert!(
        executed >= 40,
        "only {executed} cookbook commands were executed; the extractor has \
         probably stopped matching the page's code blocks, which would make \
         this gate pass by reading nothing:\n{stdout}"
    );
}
