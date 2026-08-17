// SPDX-License-Identifier: MIT OR Apache-2.0

//! A tool `scripts/preflight.sh` cannot find must never read as a gate that
//! passed.
//!
//! The script used to print `WARN` for an absent `vale` or `codespell` and end
//! the run with "Preflight clean". For a contributor without the tool that is
//! the right answer. For anything automated it is the worst one available: on
//! 2026-08-10 a background script whose hardened `PATH` omitted `~/.local/bin`
//! ran preflight, was told the tree was clean, and pushed two Vale errors that
//! turned main red (c3befb9). Nothing in the output said "command not found" —
//! the two BLOCKING gates had silently become warnings.
//!
//! `PREFLIGHT_STRICT` is the fix, and this file is the proof that it bites.
//! Every test drives the SHIPPED text of the script, extracted verbatim
//! between its `# >>> BEGIN <name>` / `# <<< END <name>` markers and executed,
//! rather than a paraphrase that can drift away from it. A tool is hidden by
//! dropping the `PATH` entries that hold it — nothing is deleted, and
//! `path_without` refuses to return a `PATH` the tool is still reachable on,
//! because a probe that quietly failed to hide anything would make every
//! assertion below pass against a tool that was there all along.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The script under test.
const SCRIPT: &str = "scripts/preflight.sh";

/// Repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// One marked block of the script, exactly as it ships.
///
/// # Panics
///
/// If either marker is missing, they are out of order, or the block is
/// implausibly short — all three would hand the tests an empty string to
/// assert against, which is the failure mode this whole file exists to reject.
fn block(name: &str) -> String {
    let path = repo().join(SCRIPT);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {SCRIPT}: {e}"));
    let begin = format!("# >>> BEGIN {name}");
    let end = format!("# <<< END {name}");

    let start = text.find(&begin).unwrap_or_else(|| {
        panic!("{SCRIPT} no longer carries {begin:?} — the block was renamed or removed")
    });
    let stop = text.find(&end).unwrap_or_else(|| {
        panic!("{SCRIPT} no longer carries {end:?} — the block was renamed or removed")
    });
    assert!(
        stop > start,
        "{SCRIPT}: {name} markers are in the wrong order"
    );

    let body = &text[start..stop];
    assert!(
        body.lines().count() > 5,
        "the extracted {name} block is only {} lines — the markers no longer \
         wrap the whole block, so these tests would drive a fragment",
        body.lines().count()
    );
    body.to_string()
}

/// An absolute interpreter path, resolved from the PATH this test process
/// inherited.
///
/// Hiding `python3` drops `/usr/bin`, which on most trees is also where `sh`
/// lives. Resolving the shell first keeps "the tool is missing" from becoming
/// "the shell is missing", which fails for a reason that has nothing to do
/// with the gate.
///
/// # Panics
///
/// If no `sh` is on PATH at all.
fn shell() -> PathBuf {
    which("sh").unwrap_or_else(|| panic!("no `sh` on PATH — these tests cannot run"))
}

/// The first PATH entry holding an executable named `tool`.
fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(tool))
        .find(|p| is_executable(p))
}

/// Whether `p` is a file this process could execute.
fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The inherited PATH with every entry holding `tool` removed.
///
/// # Panics
///
/// If `tool` is still reachable afterwards. A test that hid nothing would
/// exercise the tool-is-present arm while claiming to exercise the other one.
fn path_without(tool: &str) -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|d| !is_executable(&d.join(tool)))
        .collect();
    let joined = std::env::join_paths(kept).expect("rebuild PATH");
    assert!(
        std::env::split_paths(&joined).all(|d| !is_executable(&d.join(tool))),
        "{tool} is still on PATH after hiding it — the probe proves nothing"
    );
    joined
}

/// How a run ends: exit status and the text it printed.
struct Run {
    code: Option<i32>,
    text: String,
}

impl Run {
    /// Assert the run failed, quoting the output when it did not.
    fn assert_failed(&self, why: &str) {
        assert_eq!(
            self.code,
            Some(1),
            "{why}\nexit was {:?}, output was:\n{}",
            self.code,
            self.text
        );
        assert!(
            self.text.contains("FAIL"),
            "{why}\nthe run failed but never printed FAIL:\n{}",
            self.text
        );
    }

    /// Assert the run passed and only warned.
    fn assert_warned(&self, why: &str) {
        assert_eq!(
            self.code,
            Some(0),
            "{why}\nexit was {:?}, output was:\n{}",
            self.code,
            self.text
        );
        assert!(
            self.text.contains("WARN"),
            "{why}\nthe run passed but never printed WARN, so the missing tool \
             left no trace at all:\n{}",
            self.text
        );
    }

    /// Assert some text appears.
    fn assert_says(&self, needle: &str) {
        assert!(
            self.text.contains(needle),
            "expected the output to carry {needle:?}, got:\n{}",
            self.text
        );
    }
}

/// Everything a run needs: which blocks, what to run after them, and the
/// environment to run them in.
struct Case<'a> {
    blocks: &'a [&'a str],
    pre: String,
    tail: &'a str,
    env: Vec<(&'a str, std::ffi::OsString)>,
    cwd: PathBuf,
}

impl<'a> Case<'a> {
    fn new(blocks: &'a [&'a str]) -> Self {
        Case {
            blocks,
            pre: String::new(),
            tail: "",
            env: Vec::new(),
            cwd: repo(),
        }
    }

    /// Run the blocks with the two counters already at these values, for a
    /// block that only READS them.
    fn counts(mut self, failed: u32, degraded: u32) -> Self {
        self.pre = format!("FAILED={failed}\nDEGRADED={degraded}\n");
        self
    }

    /// Shell appended after the blocks, for a decision the blocks only record.
    fn tail(mut self, tail: &'a str) -> Self {
        self.tail = tail;
        self
    }

    fn env(mut self, key: &'a str, value: impl Into<std::ffi::OsString>) -> Self {
        self.env.push((key, value.into()));
        self
    }

    fn cwd(mut self, dir: &Path) -> Self {
        self.cwd = dir.to_path_buf();
        self
    }

    /// Run it.
    ///
    /// `CI` and `PREFLIGHT_STRICT` are removed unless the case sets them: this
    /// suite itself runs under CI, where inheriting `CI=true` would make every
    /// "a contributor is not blocked" test strict and pass for the wrong
    /// reason.
    fn run(self) -> Run {
        let mut script = String::from("GREEN=''; RED=''; YELLOW=''; NC=''\nFIX=0\n");
        script.push_str(&self.pre);
        for b in self.blocks {
            script.push_str(&block(b));
            script.push('\n');
        }
        script.push_str(self.tail);
        script.push('\n');

        let mut cmd = Command::new(shell());
        cmd.arg("-c")
            .arg(&script)
            .current_dir(&self.cwd)
            .env_remove("CI")
            .env_remove("PREFLIGHT_STRICT")
            .env_remove("CODESPELL_BIN");
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run the extracted preflight block");

        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Run {
            code: out.status.code(),
            text,
        }
    }
}

/// The blocks that decide severity, plus a line reporting the outcome.
const STATUS: &str = "status-and-strictness";

/// Ask the shipped `strict_mode` for one row of its decision table.
fn decide(terminal: &str, env: &[(&str, &str)]) -> String {
    let ask = format!("strict_mode {terminal}");
    let mut case = Case::new(&[STATUS]).tail(&ask);
    for (k, v) in env {
        case = case.env(k, *v);
    }
    let run = case.run();
    assert_eq!(run.code, Some(0), "strict_mode exited {:?}", run.code);
    run.text.trim().to_string()
}

// ---------------------------------------------------------------------------
// The decision table.
// ---------------------------------------------------------------------------

/// A human at a terminal keeps the warning. Blocking a contributor who has not
/// installed Vale helps nobody: the tool is a convenience they can add later,
/// and the local gate's job is to predict CI, not to gate on being able to.
#[test]
fn an_interactive_terminal_keeps_the_warning() {
    assert_eq!(decide("tty", &[]), "0 interactive terminal");
}

/// Output that is not a terminal is strict, with nothing else set.
///
/// This is the row that catches the incident. The background script did not
/// set `CI`; it redirected output to a log, so there was nobody to read the
/// warning it printed.
#[test]
fn output_that_is_not_a_terminal_opts_into_strict() {
    assert_eq!(decide("notty", &[]), "1 output is not a terminal");
}

/// `CI` alone is strict, even were a terminal attached. CI installs every tool
/// it needs; one missing there is a broken job, not a warning.
#[test]
fn ci_defaults_to_strict_even_at_a_terminal() {
    assert_eq!(decide("tty", &[("CI", "true")]), "1 CI is set");
}

/// An explicit `PREFLIGHT_STRICT=1` outranks the terminal.
#[test]
fn explicit_strict_overrides_the_terminal() {
    assert_eq!(
        decide("tty", &[("PREFLIGHT_STRICT", "1")]),
        "1 PREFLIGHT_STRICT=1"
    );
}

/// And an explicit `PREFLIGHT_STRICT=0` outranks `CI`, so the escape hatch
/// exists in both directions.
#[test]
fn explicit_zero_opts_out_even_under_ci() {
    assert_eq!(
        decide("notty", &[("PREFLIGHT_STRICT", "0"), ("CI", "true")]),
        "0 PREFLIGHT_STRICT=0"
    );
}

/// `strict_mode` takes the terminal answer as an argument so these tests can
/// drive both sides without a pty — which leaves exactly one line they cannot
/// reach, the `[ -t 1 ]` that supplies it. This asserts that line still wires
/// the real test to the real decision.
#[test]
fn the_decision_is_wired_to_the_real_terminal_test() {
    let body = block(STATUS);
    let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("if [ -t 1 ]; then STRICT_DECISION=$(strict_mode tty)"),
        "the strictness block no longer asks `[ -t 1 ]` for the terminal answer, \
         so `strict_mode` is being told something other than the truth:\n{body}"
    );
    assert!(
        flat.contains("strict_mode notty"),
        "nothing supplies the non-terminal answer any more:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// What the decision does.
// ---------------------------------------------------------------------------

/// Under strict, a check that could not run fails the whole script.
#[test]
fn degraded_fails_the_run_under_strict() {
    let run = Case::new(&[STATUS])
        .env("PREFLIGHT_STRICT", "1")
        .tail("degraded; printf 'FAILED=%s DEGRADED=%s\\n' \"$FAILED\" \"$DEGRADED\"; exit \"$FAILED\"")
        .run();
    run.assert_failed("PREFLIGHT_STRICT=1 must turn a check that cannot run into a failure");
    run.assert_says("FAILED=1 DEGRADED=1");
}

/// Lenient, the same check warns and the run survives.
#[test]
fn degraded_warns_without_failing_when_lenient() {
    let run = Case::new(&[STATUS])
        .env("PREFLIGHT_STRICT", "0")
        .tail("degraded; printf 'FAILED=%s DEGRADED=%s\\n' \"$FAILED\" \"$DEGRADED\"; exit \"$FAILED\"")
        .run();
    run.assert_warned("PREFLIGHT_STRICT=0 must keep a missing tool a warning");
    run.assert_says("FAILED=0 DEGRADED=1");
}

// ---------------------------------------------------------------------------
// Vale, hidden.
// ---------------------------------------------------------------------------

/// Run the vale gate with `vale` hidden from PATH.
fn vale_gate_without_vale(env: &[(&str, &str)]) -> Run {
    let mut case = Case::new(&[STATUS, "vale-gate"])
        .env("PATH", path_without("vale"))
        .tail("exit \"$FAILED\"");
    for (k, v) in env {
        case = case.env(k, *v);
    }
    case.run()
}

/// THE test of this file: strict plus a hidden `vale` exits non-zero.
#[test]
fn a_hidden_vale_fails_the_gate_under_strict() {
    let run = vale_gate_without_vale(&[("PREFLIGHT_STRICT", "1")]);
    run.assert_failed(
        "a `vale` that is not on PATH must FAIL under PREFLIGHT_STRICT=1. \
         Reporting it as a pass is how two Vale errors reached CI.",
    );
    run.assert_says("vale is not installed");
    run.assert_says("https://vale.sh");
}

/// The other half of the mutation: without strict, a contributor is warned and
/// not blocked — and the warning still carries the install hint, which is the
/// only reason the warning is worth keeping.
#[test]
fn a_hidden_vale_only_warns_for_a_contributor() {
    let run = vale_gate_without_vale(&[("PREFLIGHT_STRICT", "0")]);
    run.assert_warned("a contributor without vale must not be blocked");
    run.assert_says("https://vale.sh");
}

/// `CI` alone is enough, with nobody setting `PREFLIGHT_STRICT`.
#[test]
fn a_hidden_vale_fails_under_ci_with_nothing_else_set() {
    let run = vale_gate_without_vale(&[("CI", "true")]);
    run.assert_failed("CI must default to strict without anyone opting in");
}

/// An unreadable version pin is the same defect one level up: with nothing to
/// compare against, the comparison used to be skipped and Vale ran anyway,
/// reporting OK from a binary whose dictionary nobody had checked.
#[test]
fn an_unreadable_vale_pin_is_not_a_pass() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A tree where the workflow exists but pins nothing, and a `vale` that
    // would happily report success if the gate reached it.
    std::fs::create_dir_all(tmp.path().join(".github/workflows")).expect("mkdir workflows");
    std::fs::write(
        tmp.path().join(".github/workflows/quality.yml"),
        "name: quality\n",
    )
    .expect("write workflow");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir bin");
    stub(&bin.join("vale"), "vale version 3.16.0", 0);

    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("PATH with the stub first");

    let run = Case::new(&[STATUS, "vale-gate"])
        .env("PREFLIGHT_STRICT", "1")
        .env("PATH", path)
        .cwd(tmp.path())
        .tail("exit \"$FAILED\"")
        .run();
    run.assert_failed(
        "with no VALE_VERSION to compare against, the version check ran over \
         nothing and must not report a pass",
    );
    run.assert_says("no VALE_VERSION");
}

// ---------------------------------------------------------------------------
// codespell, hidden.
// ---------------------------------------------------------------------------

/// Run the codespell gate with `codespell` hidden from PATH.
fn codespell_gate_without_codespell(env: &[(&str, &str)]) -> Run {
    let mut case = Case::new(&[STATUS, "codespell-gate"])
        .env("PATH", path_without("codespell"))
        .tail("exit \"$FAILED\"");
    for (k, v) in env {
        case = case.env(k, *v);
    }
    case.run()
}

/// Strict plus a hidden `codespell` exits non-zero.
#[test]
fn a_hidden_codespell_fails_the_gate_under_strict() {
    let run = codespell_gate_without_codespell(&[("PREFLIGHT_STRICT", "1")]);
    run.assert_failed("a `codespell` that is not on PATH must FAIL under PREFLIGHT_STRICT=1");
    run.assert_says("pipx install codespell");
}

/// And without strict it warns, hint included.
#[test]
fn a_hidden_codespell_only_warns_for_a_contributor() {
    let run = codespell_gate_without_codespell(&[("PREFLIGHT_STRICT", "0")]);
    run.assert_warned("a contributor without codespell must not be blocked");
    run.assert_says("pipx install codespell");
}

/// A `codespell` in a venv is an installed one: `CODESPELL_BIN` is what
/// `.githooks/pre-push` accepts, and strict preflight must not fail a tree the
/// hook is happy with.
#[test]
fn codespell_bin_counts_as_installed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = tmp.path().join("codespell");
    stub(&bin, "", 0);

    let run = Case::new(&[STATUS, "codespell-gate"])
        .env("PREFLIGHT_STRICT", "1")
        .env("PATH", path_without("codespell"))
        .env("CODESPELL_BIN", bin.as_os_str())
        .tail("exit \"$FAILED\"")
        .run();
    assert_eq!(
        run.code,
        Some(0),
        "CODESPELL_BIN points at a real codespell, so strict must accept it:\n{}",
        run.text
    );
    run.assert_says("OK");
}

// ---------------------------------------------------------------------------
// The site generators, whose failure used to read as "the mirror is current".
// ---------------------------------------------------------------------------

/// Write an executable stub that prints `stdout` and exits with `code`.
fn stub(path: &Path, stdout: &str, code: i32) {
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{}'\nexit {code}\n",
            stdout.replace('\'', r"'\''")
        ),
    )
    .expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
}

/// A generator that exits non-zero rewrote nothing, so "the mirror did not
/// change" is not evidence that it was current. It used to be: both
/// generators ran under `>/dev/null 2>&1` with their status dropped.
#[test]
fn a_generator_that_exits_non_zero_is_not_a_current_mirror() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir bin");
    stub(&bin.join("python3"), "Traceback (most recent call last)", 1);

    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("PATH with the stub first");

    let run = Case::new(&[STATUS, "site-mirror-gate"])
        .env("PATH", path)
        .env("PREFLIGHT_STRICT", "0")
        .tail("exit \"$FAILED\"")
        .run();
    run.assert_failed("a crashed site generator must fail the mirror check");
    run.assert_says("exited non-zero");
}

/// And an absent `python3` degrades rather than passing: neither generator ran
/// at all, so nothing was compared.
#[test]
fn a_hidden_python3_fails_the_site_mirror_gate_under_strict() {
    let run = Case::new(&[STATUS, "site-mirror-gate"])
        .env("PATH", path_without("python3"))
        .env("PREFLIGHT_STRICT", "1")
        .tail("exit \"$FAILED\"")
        .run();
    run.assert_failed("without python3 the site mirrors were never regenerated");
    run.assert_says("python3 is not installed");
}

// ---------------------------------------------------------------------------
// The `cd` to the repository root, which was never the guard it looked like.
// ---------------------------------------------------------------------------

/// Without git there is no repository root, and every check below reads the
/// repository — so the script must stop.
///
/// `cd "$(git rev-parse --show-toplevel)" || exit 1` did not do that: the
/// substitution came back empty, `cd ""` returns 0 in bash without moving, and
/// the run went on to measure whatever directory it had been started from.
#[test]
fn no_git_stops_the_run_rather_than_measuring_the_wrong_tree() {
    let run = Case::new(&["repo-root"])
        .env("PATH", path_without("git"))
        .tail("printf 'REACHED %s\\n' \"$PWD\"")
        .run();
    assert_ne!(
        run.code,
        Some(0),
        "with git hidden the script must not continue:\n{}",
        run.text
    );
    assert!(
        !run.text.contains("REACHED"),
        "the guard let the run continue past it:\n{}",
        run.text
    );
    run.assert_says("not inside a git repository");
}

/// And with git present it still moves to the root, from wherever it was
/// started — the behavior the broken guard was hiding.
#[test]
fn the_run_moves_to_the_repository_root() {
    let run = Case::new(&["repo-root"])
        .cwd(&repo().join("tests"))
        .tail("printf 'PWD=%s\\n' \"$PWD\"")
        .run();
    assert_eq!(run.code, Some(0), "a real repository must not stop the run");
    run.assert_says(&format!("PWD={}", repo().display()));
}

// ---------------------------------------------------------------------------
// The closing summary.
// ---------------------------------------------------------------------------

/// "Preflight clean" is the sentence the script printed on 2026-08-10 while
/// two blocking gates had not run. It may not print it again over a warning.
#[test]
fn a_degraded_run_is_never_reported_clean() {
    // The summary block only READS the two counters, so they are set directly:
    // what is under test is the sentence, not how the counts got there.
    let run = Case::new(&["summary"]).counts(0, 1).run();
    assert_eq!(run.code, Some(0), "a warning does not fail the run");
    assert!(
        !run.text.contains("Preflight clean."),
        "a run with a check that could not run must not be called clean:\n{}",
        run.text
    );
    run.assert_says("MINUS 1 check(s) that could not run");
}

/// A run with nothing degraded still says so plainly, so the sentence above
/// is not simply unreachable.
#[test]
fn an_undegraded_run_still_reports_clean() {
    let run = Case::new(&["summary"]).counts(0, 0).run();
    assert_eq!(run.code, Some(0));
    run.assert_says("Preflight clean.");
}
