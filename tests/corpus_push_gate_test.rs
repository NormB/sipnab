// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pre-push corpus gate must actually block, and must keep deriving its
//! target list from the tree.
//!
//! `tests/corpus_skip_notice_test.rs` gates the other half of #134: an absent
//! corpus is audible rather than silent. This file gates the half that runs
//! when the corpus IS present — the `.githooks/pre-push` block that drives
//! every corpus binary and refuses the push when one fails.
//!
//! Until this file existed that block had no gate of its own. Deleting it, or
//! dropping its `exit 1`, or quietly replacing the derived target list with a
//! hand-written one, all left a green tree — which is precisely the failure
//! the block was written to prevent, one layer up. A gate with no gate is a
//! promise, and this project does not ship promises.
//!
//! The block is not re-implemented here. It is extracted VERBATIM between the
//! `BEGIN corpus-gate` / `END corpus-gate` markers and executed with a stub
//! `cargo` on `PATH`, so what these tests prove is the shipped text and not a
//! paraphrase of it that can drift away from it.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The hook this file gates.
const HOOK: &str = ".githooks/pre-push";

const BEGIN: &str = "# >>> BEGIN corpus-gate";
const END: &str = "# <<< END corpus-gate";

/// Repository root.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The corpus gate, exactly as it ships.
///
/// # Panics
///
/// If either marker is missing, or the block between them is implausibly
/// short. Both are failures of this test's own premise: a silent empty
/// extraction would make every assertion below pass against nothing.
fn extract_gate() -> String {
    let hook = std::fs::read_to_string(repo_root().join(HOOK))
        .unwrap_or_else(|e| panic!("read {HOOK}: {e}"));

    let start = hook.find(BEGIN).unwrap_or_else(|| {
        panic!("{HOOK} no longer carries {BEGIN:?} — the corpus gate has been moved or deleted")
    });
    let end = hook.find(END).unwrap_or_else(|| {
        panic!("{HOOK} no longer carries {END:?} — the corpus gate has been moved or deleted")
    });
    assert!(
        end > start,
        "{HOOK} has the corpus-gate markers in the wrong order"
    );

    let block = &hook[start..end];
    assert!(
        block.lines().count() > 80,
        "the extracted corpus gate is only {} lines — the markers are no longer \
         wrapped around the whole block, so these tests would drive a fragment",
        block.lines().count()
    );
    block.to_string()
}

/// Build a runnable script from the shipped block plus the environment the
/// hook itself supplies above it (colours only — everything else the block
/// needs, it defines).
fn runnable_gate() -> String {
    format!(
        "set -eu\n\
         GREEN=''; RED=''; YELLOW=''; NC=''\n\
         {}\n",
        extract_gate()
    )
}

/// Write a `cargo` stub that exits with `code`, and return the directory to
/// put on `PATH`.
fn stub_cargo(dir: &Path, code: i32, stdout: &str) {
    let bin = dir.join("cargo");
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' {}\nexit {code}\n",
            shell_quote(stdout)
        ),
    )
    .expect("write cargo stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .expect("chmod cargo stub");
    }
}

/// Single-quote for `sh`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// One run of the extracted gate: its exit status, its combined output, and
/// the gitdir it was pointed at.
///
/// `_tmp` owns that gitdir. Dropping the `TempDir` deletes it, so a caller
/// that inspected [`Self::corpus_log`] after the struct died would be reading
/// a path that no longer exists — and an `!exists()` assertion would pass for
/// the wrong reason.
struct GateRun {
    code: Option<i32>,
    text: String,
    gitdir: PathBuf,
    _tmp: tempfile::TempDir,
}

impl GateRun {
    /// The log the gate writes when the corpus fails.
    fn corpus_log(&self) -> PathBuf {
        self.gitdir.join("sipnab-pre-push-corpus.log")
    }
}

/// Run the extracted gate with a stubbed `cargo` and a corpus directory that
/// exists, so the gate takes its `run)` arm.
fn run_gate(cargo_exit: i32, cargo_stdout: &str) -> GateRun {
    run_gate_seeded(cargo_exit, cargo_stdout, None)
}

/// As [`run_gate`], first seeding `seed_log` into the gitdir as a stale log.
///
/// The gate resolves its log directory with `git rev-parse --git-dir`, so this
/// harness hands it a throwaway `GIT_DIR`. Without that it resolves the REAL
/// `.git` of this repository and writes its synthetic failure there: a fully
/// GREEN run of this file left `.git/sipnab-pre-push-corpus.log` holding a
/// `... FAILED` line, and two readers took that stale copy for a live
/// regression before the cause was traced back to here.
///
/// The throwaway must be a real repository. `git rev-parse --git-dir` exits
/// 128 on a `GIT_DIR` that is merely an empty directory, and the gate falls
/// back to `.` on a non-zero rev-parse — which, with the cwd below, would put
/// the log in the WORKING TREE. That is worse than the bug this replaces, so
/// the directory is initialised rather than just created.
fn run_gate_seeded(cargo_exit: i32, cargo_stdout: &str, seed_log: Option<&str>) -> GateRun {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bindir = tmp.path().join("bin");
    let corpus = tmp.path().join("corpus");
    let gitdir = tmp.path().join("gitdir");
    std::fs::create_dir_all(&bindir).expect("mkdir bin");
    std::fs::create_dir_all(&corpus).expect("mkdir corpus");
    stub_cargo(&bindir, cargo_exit, cargo_stdout);

    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&gitdir)
        .output()
        .expect("git init the throwaway gitdir");
    assert!(
        init.status.success(),
        "could not initialise a throwaway gitdir, so this run would write its log \
         into the real repository: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    if let Some(body) = seed_log {
        std::fs::write(gitdir.join("sipnab-pre-push-corpus.log"), body).expect("seed stale log");
    }

    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()).expect("write gate");

    let path = format!(
        "{}:{}",
        bindir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = Command::new("sh")
        .arg(&script)
        // The block derives its target list from `tests/*.rs`, so it must run
        // where those live ...
        .current_dir(repo_root())
        // ... but its log must NOT land there. See the note above.
        .env("GIT_DIR", &gitdir)
        .env("PATH", path)
        .env("SIPNAB_CORPUS", &corpus)
        .env_remove("SKIP_CORPUS_HOOK")
        .output()
        .expect("run corpus gate");

    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    GateRun {
        code: out.status.code(),
        text,
        gitdir,
        _tmp: tmp,
    }
}

/// A failing corpus run blocks the push.
///
/// THE test of this file. Everything else is a way of keeping this one
/// honest: it asserts the effect — a non-zero exit — rather than the presence
/// of an `exit 1` in the source, which survives being commented out.
#[test]
fn a_failing_corpus_run_blocks_the_push() {
    let run = run_gate(
        101,
        "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
         test result: FAILED. 0 passed; 1 failed; 0 ignored",
    );
    let text = &run.text;
    assert_ne!(
        run.code,
        Some(0),
        "the corpus gate let a FAILING corpus run through. Anything short of 100% \
         against the corpus is a critical failure and must not reach a push. \
         Gate output was:\n{text}"
    );
    assert!(
        text.contains("FAIL"),
        "a blocked push must say the corpus failed: {text}"
    );
}

/// The failure log lands in the gitdir the gate was GIVEN, never this repo's.
///
/// The mutation that matters is dropping the `GIT_DIR` line from
/// `run_gate_seeded`: the gate then resolves the real `.git`, the file below
/// never appears in the throwaway, and this fails. That is the whole point —
/// a self-test for a gate must not write into the tree it is gating, and for
/// one release this one did.
#[test]
fn a_failing_run_writes_its_log_into_the_gitdir_it_was_given() {
    let run = run_gate(
        101,
        "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
         test result: FAILED. 0 passed; 1 failed; 0 ignored",
    );
    let log = run.corpus_log();
    assert!(
        log.is_file(),
        "the gate did not write its log to the gitdir it was pointed at ({}). \
         It resolved somewhere else — most likely the real .git of this \
         repository. Gate output was:\n{}",
        log.display(),
        run.text
    );
    let body = std::fs::read_to_string(&log).expect("read corpus log");
    assert!(
        body.contains("every_dialog_diagnoses"),
        "the log exists but does not hold the run's output: {body}"
    );
}

/// A clean run leaves NO failure log behind.
///
/// The log records the LAST run, not every run that ever failed. Without this
/// a failure written weeks ago outlives every green push after it, and the
/// gitdir goes on asserting a regression that is already fixed.
#[test]
fn a_clean_corpus_run_clears_a_stale_failure_log() {
    let run = run_gate_seeded(
        0,
        "test result: ok. 25 passed; 0 failed; 0 ignored",
        Some(
            "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
             test result: FAILED. 0 passed; 1 failed; 0 ignored\n",
        ),
    );
    assert_eq!(
        run.code,
        Some(0),
        "a clean corpus run must not block the push: {}",
        run.text
    );
    let log = run.corpus_log();
    assert!(
        !log.exists(),
        "a VALIDATED corpus run left a stale failure log at {}, so the next \
         reader finds a `... FAILED` line describing a run that passed. \
         Contents:\n{}",
        log.display(),
        std::fs::read_to_string(&log).unwrap_or_default()
    );
}

/// A clean corpus run does not block, and says so.
///
/// The other half of the mutation: a gate hard-wired to `exit 1` would pass
/// the test above and fail this one, so neither alone is enough.
#[test]
fn a_clean_corpus_run_passes_and_reports_validated() {
    let run = run_gate(0, "test result: ok. 25 passed; 0 failed; 0 ignored");
    let text = &run.text;
    assert_eq!(
        run.code,
        Some(0),
        "a clean corpus run must not block the push. Gate output was:\n{text}"
    );
    assert!(
        text.contains("VALIDATED"),
        "a clean corpus run must report VALIDATED, or a reader cannot tell it from \
         a skip: {text}"
    );
}

/// The gate names every corpus binary it will drive, and the count is real.
#[test]
fn the_gate_reports_the_number_of_binaries_it_drives() {
    let text = run_gate(0, "test result: ok. 25 passed; 0 failed; 0 ignored").text;
    let expected = corpus_binaries().len();
    assert!(
        text.contains(&format!("corpus: {expected} test binaries")),
        "the gate must announce how many binaries it drives, and it must match the \
         {expected} sources that read SIPNAB_CORPUS: {text}"
    );
}

/// Every `tests/*.rs` that reads the corpus variable — the set the hook derives.
fn corpus_binaries() -> Vec<String> {
    let dir = repo_root().join("tests");
    let mut out: Vec<String> = std::fs::read_dir(&dir)
        .expect("read tests/")
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter(|p| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .contains("SIPNAB_CORPUS")
        })
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// The target list is DERIVED from the tree, never hand-listed.
///
/// The hook's own comment records why: the first draft hand-listed the
/// binaries and went stale within the hour, so a twelfth corpus binary would
/// have been skipped while the gate printed VALIDATED. A hand-written list
/// cannot catch a NEW member, which is the one thing this gate is for.
#[test]
fn the_gate_derives_its_targets_rather_than_naming_them() {
    let gate = extract_gate();
    assert!(
        gate.contains("grep -lE") && gate.contains("SIPNAB_CORPUS") && gate.contains("tests/*.rs"),
        "the corpus gate no longer derives its target list from tests/*.rs"
    );

    // A literal `--test <name>` for a real corpus binary is the signature of a
    // hand-kept list creeping back in.
    for name in corpus_binaries() {
        assert!(
            !gate.contains(&format!("--test {name}")),
            "the corpus gate names {name} literally; the list must stay derived so a \
             NEW corpus binary is picked up without anyone remembering to add it"
        );
    }

    assert!(
        corpus_binaries().len() >= 11,
        "only {} tests/*.rs read SIPNAB_CORPUS; the corpus suite is being removed, or \
         this test is now measuring nothing",
        corpus_binaries().len()
    );
}

/// The bypass exists, is its own variable, and says the corpus was not validated.
///
/// A bypass that printed nothing would be indistinguishable from a clean run,
/// which is the same silent-zero shape the whole ticket is about.
#[test]
fn the_bypass_is_loud_and_separate_from_the_blanket_skip() {
    let gate = extract_gate();
    assert!(
        gate.contains("SKIP_CORPUS_HOOK"),
        "the corpus gate has no dedicated bypass, so the only way past it is \
         SKIP_FMT_HOOK, which drops every other gate too"
    );
    assert!(
        !gate.contains("SKIP_FMT_HOOK"),
        "the corpus gate must not key off the blanket bypass: reaching for it to \
         skip the corpus silently drops the five other gates as well"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()).expect("write gate");
    let out = Command::new("sh")
        .arg(&script)
        .current_dir(repo_root())
        .env("SKIP_CORPUS_HOOK", "1")
        .env_remove("SIPNAB_CORPUS")
        .output()
        .expect("run corpus gate");

    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a bypass must not block: {text}"
    );
    assert!(
        text.contains("BYPASSED") && text.contains("NOT validated"),
        "a bypassed corpus must say so on the record, or the push it let through \
         reads exactly like a validated one: {text}"
    );
}

/// An unset corpus is a skip that announces itself, not a silent pass.
#[test]
fn an_unset_corpus_is_announced_rather_than_passed_over() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()).expect("write gate");
    let out = Command::new("sh")
        .arg(&script)
        .current_dir(repo_root())
        .env_remove("SIPNAB_CORPUS")
        .env_remove("SKIP_CORPUS_HOOK")
        .output()
        .expect("run corpus gate");

    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a contributor without the corpus must still be able to push: {text}"
    );
    assert!(
        text.contains("NOT VALIDATED") && text.contains("SIPNAB_CORPUS"),
        "an unset corpus must name itself and deny validation, or a wall of OK lines \
         reads as 'corpus validated': {text}"
    );
}
