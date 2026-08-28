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
//! - **UNCOVERED** — neither, and it FAILS the run. A checker that ignores what
//!   it cannot handle reports a clean page by not looking at it, which is the
//!   shape [[feedback_empty_output_is_not_evidence]] warns about and the reason
//!   RDR2 is open. Counting them without failing was that same shape with a
//!   number printed beside it: the count sat at 1 for as long as recipe 12's
//!   second pass existed, and every run was green.
//!
//! A command that genuinely cannot be covered goes in the checker's
//! `UNCOVERABLE` table WITH the reason, and the checker refuses an entry that
//! states none — or one that exempts nothing, which is the same skip list a
//! year later. The table is empty today; the tests below prove the two rules
//! fire anyway, because a rule only exercised by an empty list is a rule
//! nobody has run.
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
    let count = |label: &str| -> Option<u32> {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix(label))
            .and_then(|rest| rest.trim().strip_prefix(':'))
            .and_then(|n| n.trim().parse::<u32>().ok())
    };

    let executed = count("executed against a fixture").unwrap_or(0);
    // Was 40 against 49 executed. Raised with the change attributed: recipe
    // 12's second pass — `--call-report "$cid"` inside a `while read` loop —
    // is the fiftieth, and it became executable when the shell-variable test
    // moved to AFTER placeholder substitution. `$cid` is the same placeholder
    // as the page's own `abc123@host`, and a real Call-ID out of the fixture
    // replaces both.
    assert!(
        executed >= 45,
        "only {executed} cookbook commands were executed; the extractor has \
         probably stopped matching the page's code blocks, which would make \
         this gate pass by reading nothing:\n{stdout}"
    );

    // The checker prints this line unconditionally, so a missing line means
    // the summary changed shape and this assertion had stopped reading
    // anything — which is the failure it exists to catch.
    let uncovered = count("UNCOVERED").unwrap_or_else(|| {
        panic!("the checker printed no UNCOVERED count; its summary has changed shape:\n{stdout}")
    });
    assert_eq!(
        uncovered, 0,
        "{uncovered} cookbook command(s) are covered by no check at all. \
         Either make them checkable, or record each one in `UNCOVERABLE` in \
         scripts/check-cookbook.py with the reason it cannot be:\n{stdout}"
    );
}

/// Run the checker with extra arguments, returning (status code, stdout+stderr).
fn checker(extra: &[&str]) -> (Option<i32>, String) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3")
        .arg(repo.join("scripts/check-cookbook.py"))
        .args(extra)
        .current_dir(repo)
        .output()
        .expect("run scripts/check-cookbook.py (python3 must be on PATH)");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

/// Every exemption on record states a reason.
///
/// Read out of the checker itself (`--dump-exemptions`) rather than re-parsed
/// from its source, so this inspects the table the run actually uses.
///
/// The table is empty today. That makes this assertion vacuous ON ITS OWN,
/// which is exactly why the injected entry below is part of the same test: it
/// proves the dump reports entries when there are entries, so an empty result
/// means an empty table rather than a reader that stopped reading.
#[test]
fn every_recorded_cookbook_exemption_states_a_reason() {
    let (code, dump) = checker(&["--dump-exemptions"]);
    assert_eq!(code, Some(0), "--dump-exemptions failed:\n{dump}");

    for line in dump.lines().filter(|l| !l.trim().is_empty()) {
        let (pattern, reason) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("exemption line is not `pattern<TAB>reason`: {line:?}"));
        assert!(
            !pattern.trim().is_empty() && !reason.trim().is_empty(),
            "the cookbook exemption {pattern:?} states no reason. An exemption \
             without one outlives the person who knew why, and the next reader \
             cannot tell a real constraint from a command nobody fixed."
        );
    }

    let (code, dump) = checker(&["--dump-exemptions", "--exempt", "sipnab -N=a stated reason"]);
    assert_eq!(
        code,
        Some(0),
        "--dump-exemptions with an entry failed:\n{dump}"
    );
    assert_eq!(
        dump.trim(),
        "sipnab -N\ta stated reason",
        "the exemption dump did not report an entry that was definitely there, \
         so the loop above proves nothing about an empty table"
    );
}

/// The checker REFUSES an exemption with no stated reason.
///
/// The effect, not the predicate: this drives the checker rather than reading
/// its source for a validator that might never be called. Cheap on purpose —
/// the reason check runs before the binary is opened, so nothing is executed.
#[test]
fn an_exemption_without_a_stated_reason_is_refused() {
    let (code, text) = checker(&["--exempt", "sipnab -N="]);
    assert_eq!(
        code,
        Some(2),
        "the checker accepted an exemption with an empty reason, so its skip \
         list demands nothing and will rot into one:\n{text}"
    );
    assert!(
        text.contains("states no reason"),
        "exit 2, but not for the missing reason — so this test would pass on \
         an unrelated failure:\n{text}"
    );

    let (code, text) = checker(&["--exempt", "=a stated reason"]);
    assert_eq!(
        code,
        Some(2),
        "the checker accepted an exemption with an empty PATTERN, which \
         matches every command in the page:\n{text}"
    );
    assert!(
        text.contains("empty pattern"),
        "exit 2, but not for the empty pattern:\n{text}"
    );
}
