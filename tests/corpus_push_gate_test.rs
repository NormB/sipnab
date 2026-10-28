// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

#[path = "support/executable.rs"]
mod executable;

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
fn extract_gate() -> Result<String, TestError> {
    let hook =
        std::fs::read_to_string(repo_root().join(HOOK)).map_err(|e| format!("read {HOOK}: {e}"))?;

    let start = hook.find(BEGIN).ok_or_else(|| {
        format!("{HOOK} no longer carries {BEGIN:?} — the corpus gate has been moved or deleted")
    })?;
    let end = hook.find(END).ok_or_else(|| {
        format!("{HOOK} no longer carries {END:?} — the corpus gate has been moved or deleted")
    })?;
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
    Ok(block.to_string())
}

/// Build a runnable script from the shipped block plus the environment the
/// hook itself supplies above it (colors only — everything else the block
/// needs, it defines).
fn runnable_gate() -> Result<String, TestError> {
    Ok(format!(
        "set -eu\n\
         GREEN=''; RED=''; YELLOW=''; NC=''\n\
         {}\n",
        extract_gate()?
    ))
}

/// Write a `cargo` stub that exits with `code`, and return the directory to
/// put on `PATH`.
fn stub_cargo(dir: &Path, code: i32, stdout: &str) -> Result<(), TestError> {
    let bin = dir.join("cargo");
    executable::write_executable(
        &bin,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' {}\nexit {code}\n",
            shell_quote(stdout)
        ),
    )?;
    Ok(())
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
fn run_gate(cargo_exit: i32, cargo_stdout: &str) -> Result<GateRun, TestError> {
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
/// the directory is initialized rather than just created.
fn run_gate_seeded(
    cargo_exit: i32,
    cargo_stdout: &str,
    seed_log: Option<&str>,
) -> Result<GateRun, TestError> {
    let tmp = tempfile::tempdir()?;
    let bindir = tmp.path().join("bin");
    let corpus = tmp.path().join("corpus");
    let gitdir = tmp.path().join("gitdir");
    std::fs::create_dir_all(&bindir)?;
    std::fs::create_dir_all(&corpus)?;
    stub_cargo(&bindir, cargo_exit, cargo_stdout)?;

    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&gitdir)
        .output()?;
    assert!(
        init.status.success(),
        "could not initialize a throwaway gitdir, so this run would write its log \
         into the real repository: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    if let Some(body) = seed_log {
        std::fs::write(gitdir.join("sipnab-pre-push-corpus.log"), body)?;
    }

    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()?)?;

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
        .output()?;

    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(GateRun {
        code: out.status.code(),
        text,
        gitdir,
        _tmp: tmp,
    })
}

/// A failing corpus run blocks the push.
///
/// THE test of this file. Everything else is a way of keeping this one
/// honest: it asserts the effect — a non-zero exit — rather than the presence
/// of an `exit 1` in the source, which survives being commented out.
#[test]
fn a_failing_corpus_run_blocks_the_push() -> Result<(), TestError> {
    let run = run_gate(
        101,
        "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
         test result: FAILED. 0 passed; 1 failed; 0 ignored",
    )?;
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
    Ok(())
}

/// The failure log lands in the gitdir the gate was GIVEN, never this repo's.
///
/// The mutation that matters is dropping the `GIT_DIR` line from
/// `run_gate_seeded`: the gate then resolves the real `.git`, the file below
/// never appears in the throwaway, and this fails. That is the whole point —
/// a self-test for a gate must not write into the tree it is gating, and for
/// one release this one did.
#[test]
fn a_failing_run_writes_its_log_into_the_gitdir_it_was_given() -> Result<(), TestError> {
    let run = run_gate(
        101,
        "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
         test result: FAILED. 0 passed; 1 failed; 0 ignored",
    )?;
    let log = run.corpus_log();
    assert!(
        log.is_file(),
        "the gate did not write its log to the gitdir it was pointed at ({}). \
         It resolved somewhere else — most likely the real .git of this \
         repository. Gate output was:\n{}",
        log.display(),
        run.text
    );
    let body = std::fs::read_to_string(&log)?;
    assert!(
        body.contains("every_dialog_diagnoses"),
        "the log exists but does not hold the run's output: {body}"
    );
    Ok(())
}

/// A clean run leaves NO failure log behind.
///
/// The log records the LAST run, not every run that ever failed. Without this
/// a failure written weeks ago outlives every green push after it, and the
/// gitdir goes on asserting a regression that is already fixed.
#[test]
fn a_clean_corpus_run_clears_a_stale_failure_log() -> Result<(), TestError> {
    let run = run_gate_seeded(
        0,
        "test result: ok. 25 passed; 0 failed; 0 ignored",
        Some(
            "test corpus_diagnosis::every_dialog_diagnoses ... FAILED\n\
             test result: FAILED. 0 passed; 1 failed; 0 ignored\n",
        ),
    )?;
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
    Ok(())
}

/// A clean corpus run does not block, and says so.
///
/// The other half of the mutation: a gate hard-wired to `exit 1` would pass
/// the test above and fail this one, so neither alone is enough.
#[test]
fn a_clean_corpus_run_passes_and_reports_validated() -> Result<(), TestError> {
    let run = run_gate(0, "test result: ok. 25 passed; 0 failed; 0 ignored")?;
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
    Ok(())
}

/// The gate names every corpus binary it will drive, and the count is real.
#[test]
fn the_gate_reports_the_number_of_binaries_it_drives() -> Result<(), TestError> {
    let text = run_gate(0, "test result: ok. 25 passed; 0 failed; 0 ignored")?.text;
    let expected = corpus_binaries()?.len();
    assert!(
        text.contains(&format!("corpus: {expected} test binaries")),
        "the gate must announce how many binaries it drives, and it must match the \
         {expected} sources that read SIPNAB_CORPUS: {text}"
    );
    Ok(())
}

/// The two variables that point a test at private data the repository does
/// not hold: the capture corpus and the vCon dataset cache.
const CORPUS_VARS: [&str; 2] = ["SIPNAB_CORPUS", "SIPNAB_VCON_DATASETS"];

/// Whether `text` names one of [`CORPUS_VARS`] as a whole word, so a longer
/// name that merely starts with one does not count.
fn names_a_corpus_var(text: &str) -> bool {
    CORPUS_VARS.iter().any(|var| {
        text.match_indices(var).any(|(at, _)| {
            let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
            let before = text[..at].chars().next_back().is_none_or(|c| !word(c));
            let after = text[at + var.len()..]
                .chars()
                .next()
                .is_none_or(|c| !word(c));
            before && after
        })
    })
}

/// Every `.rs` file under `dir`, recursively, sorted.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(|e| format!("read {}: {e}", d.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// What reads the corpus in `root`, worked out independently of the hook.
///
/// A test binary reads the corpus when its own source names one of
/// [`CORPUS_VARS`], or when it mounts (`#[path = "support/x.rs"]`) a support
/// file that does. `binaries` holds those binaries. `undrivable` holds every
/// other source file that names a variable: a lib or bin unit test, or a file
/// under `tests/` no binary mounts. `cargo test --test <name>` cannot reach
/// any of them, so the corpus gate never runs them.
struct CorpusReaders {
    binaries: Vec<String>,
    undrivable: Vec<PathBuf>,
}

fn corpus_readers(root: &Path) -> Result<CorpusReaders, TestError> {
    let tests = root.join("tests");
    let mut binaries = std::collections::BTreeSet::new();
    let mut undrivable = Vec::new();
    // Top-level tests/*.rs: each one is a cargo test target.
    let mut targets = Vec::new();
    for entry in std::fs::read_dir(&tests)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|x| x == "rs") {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .ok_or_else(|| format!("{} has no file stem", path.display()))?;
            targets.push((stem, std::fs::read_to_string(&path)?));
        }
    }
    let mut readers = Vec::new();
    for dir in ["src", "tests", "benches", "examples"] {
        let dir = root.join(dir);
        if dir.is_dir() {
            readers.extend(rust_files(&dir)?);
        }
    }
    for path in readers {
        if !names_a_corpus_var(&std::fs::read_to_string(&path)?) {
            continue;
        }
        let Ok(rel) = path.strip_prefix(&tests) else {
            undrivable.push(path);
            continue;
        };
        if rel.components().count() == 1 {
            let stem = rel.file_stem().map(|s| s.to_string_lossy().into_owned());
            binaries.extend(stem);
            continue;
        }
        // A support file: driven through every binary that mounts it.
        let mount = format!("\"{}\"", rel.to_string_lossy());
        let mounted_by: Vec<&String> = targets
            .iter()
            .filter(|(_, text)| text.contains(&mount))
            .map(|(stem, _)| stem)
            .collect();
        if mounted_by.is_empty() {
            undrivable.push(path);
        }
        binaries.extend(mounted_by.into_iter().cloned());
    }
    Ok(CorpusReaders {
        binaries: binaries.into_iter().collect(),
        undrivable,
    })
}

/// Every test binary that reads the corpus — the set the hook must derive.
fn corpus_binaries() -> Result<Vec<String>, TestError> {
    Ok(corpus_readers(&repo_root())?.binaries)
}

/// The `--test` targets the gate hands `cargo` when run with `tree` as its
/// working directory: the gate runs with a stub `cargo` that records its
/// arguments, so this is what the gate DID, not what its text says.
fn gate_targets(tree: &Path) -> Result<Vec<String>, TestError> {
    let tmp = tempfile::tempdir()?;
    let bindir = tmp.path().join("bin");
    let corpus = tmp.path().join("corpus");
    let gitdir = tmp.path().join("gitdir");
    let args = tmp.path().join("cargo-args");
    std::fs::create_dir_all(&bindir)?;
    std::fs::create_dir_all(&corpus)?;
    executable::write_executable(
        &bindir.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n\
             printf '%s\\n' 'test result: ok. 1 passed; 0 failed; 0 ignored'\n",
            shell_quote(&args.to_string_lossy())
        ),
    )?;
    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&gitdir)
        .output()?;
    assert!(
        init.status.success(),
        "could not initialize a throwaway gitdir: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()?)?;
    let out = Command::new("sh")
        .arg(&script)
        .current_dir(tree)
        .env("GIT_DIR", &gitdir)
        .env(
            "PATH",
            format!(
                "{}:{}",
                bindir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("SIPNAB_CORPUS", &corpus)
        .env_remove("SKIP_CORPUS_HOOK")
        .output()?;
    let recorded = std::fs::read_to_string(&args).map_err(|e| {
        format!(
            "the gate never ran cargo ({e}); its output was:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })?;
    let words: Vec<&str> = recorded.lines().collect();
    let mut targets: Vec<String> = words
        .windows(2)
        .filter(|w| w[0] == "--test")
        .map(|w| w[1].to_owned())
        .collect();
    targets.sort();
    Ok(targets)
}

/// pre-push drives every test binary in the tree that reads the corpus.
///
/// It is the only place the corpus runs: the pre-commit test pool runs
/// without `SIPNAB_CORPUS` and `SIPNAB_VCON_DATASETS`
/// (`scripts/test-pre-commit.sh`, Scenario 1c), and CI never holds the
/// captures. So a reader this gate does not drive is a reader nothing runs.
/// The set is worked out here from the whole tree, `src/` included, and
/// compared with the `--test` targets the gate actually handed `cargo`.
#[test]
fn the_gate_drives_every_corpus_reader_in_the_tree() -> Result<(), TestError> {
    let readers = corpus_readers(&repo_root())?;
    assert!(
        readers.undrivable.is_empty(),
        "these files read the corpus, but no `cargo test --test` target holds them, so \
         the pre-push corpus gate cannot run them and nothing else does. Move each \
         one into a tests/*.rs binary: {:?}",
        readers.undrivable
    );
    let driven = gate_targets(&repo_root())?;
    let missing: Vec<&String> = readers
        .binaries
        .iter()
        .filter(|b| !driven.contains(b))
        .collect();
    assert!(
        missing.is_empty(),
        "these test binaries read the corpus but the pre-push gate does not drive \
         them: {missing:?}. The gate drove: {driven:?}"
    );
    Ok(())
}

/// A synthetic tree pins the rule at its edges.
///
/// * A binary that reads the corpus only through a mounted support file is
///   driven, as is one that names only `SIPNAB_VCON_DATASETS`.
/// * Negative control: a binary that reads nothing is not driven, so the
///   gate is not passing by driving every target.
/// * Edge: a binary that only mentions the support file's name in a comment,
///   without mounting it, is not driven either.
#[test]
fn the_gate_finds_readers_by_variable_and_by_mounted_support() -> Result<(), TestError> {
    let tree = tempfile::tempdir()?;
    let tests = tree.path().join("tests");
    std::fs::create_dir_all(tests.join("support"))?;
    let write = |name: &str, body: &str| std::fs::write(tests.join(name), body);
    write(
        "support/corpus.rs",
        "pub fn root() -> Option<String> { std::env::var(\"SIPNAB_CORPUS\").ok() }\n",
    )?;
    write(
        "names_corpus_test.rs",
        "fn f() { std::env::var(\"SIPNAB_CORPUS\"); }\n",
    )?;
    write(
        "names_datasets_test.rs",
        "fn f() { std::env::var(\"SIPNAB_VCON_DATASETS\"); }\n",
    )?;
    write(
        "mounts_support_test.rs",
        "#[path = \"support/corpus.rs\"]\nmod corpus_support;\n",
    )?;
    write(
        "mentions_support_test.rs",
        "// see tests/support/corpus.rs for how the corpus is found\n",
    )?;
    write("reads_nothing_test.rs", "fn f() {}\n")?;

    let driven = gate_targets(tree.path())?;
    assert_eq!(
        driven,
        [
            "mounts_support_test",
            "names_corpus_test",
            "names_datasets_test"
        ],
        "the gate must drive exactly the binaries that read the corpus"
    );
    assert_eq!(
        corpus_readers(tree.path())?.binaries,
        driven,
        "this file's own rule and the gate disagree about the synthetic tree"
    );
    Ok(())
}

/// The target list is DERIVED from the tree, never hand-listed.
///
/// The hook's own comment records why: the first draft hand-listed the
/// binaries and went stale within the hour, so a twelfth corpus binary would
/// have been skipped while the gate printed VALIDATED. A hand-written list
/// cannot catch a NEW member, which is the one thing this gate is for.
#[test]
fn the_gate_derives_its_targets_rather_than_naming_them() -> Result<(), TestError> {
    let gate = extract_gate()?;
    assert!(
        gate.contains("grep -lE") && gate.contains("SIPNAB_CORPUS") && gate.contains("tests/*.rs"),
        "the corpus gate no longer derives its target list from tests/*.rs"
    );

    // A literal `--test <name>` for a real corpus binary is the signature of a
    // hand-kept list creeping back in.
    for name in corpus_binaries()? {
        assert!(
            !gate.contains(&format!("--test {name}")),
            "the corpus gate names {name} literally; the list must stay derived so a \
             NEW corpus binary is picked up without anyone remembering to add it"
        );
    }

    assert!(
        corpus_binaries()?.len() >= 11,
        "only {} tests/*.rs read SIPNAB_CORPUS; the corpus suite is being removed, or \
         this test is now measuring nothing",
        corpus_binaries()?.len()
    );
    Ok(())
}

/// The bypass exists, is its own variable, and says the corpus was not validated.
///
/// A bypass that printed nothing would be indistinguishable from a clean run,
/// which is the same silent-zero shape the whole ticket is about.
#[test]
fn the_bypass_is_loud_and_separate_from_the_blanket_skip() -> Result<(), TestError> {
    let gate = extract_gate()?;
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

    let tmp = tempfile::tempdir()?;
    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()?)?;
    let out = Command::new("sh")
        .arg(&script)
        .current_dir(repo_root())
        .env("SKIP_CORPUS_HOOK", "1")
        .env_remove("SIPNAB_CORPUS")
        .output()?;

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
    Ok(())
}

/// An unset corpus is a skip that announces itself, not a silent pass.
#[test]
fn an_unset_corpus_is_announced_rather_than_passed_over() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let script = tmp.path().join("gate.sh");
    std::fs::write(&script, runnable_gate()?)?;
    let out = Command::new("sh")
        .arg(&script)
        .current_dir(repo_root())
        .env_remove("SIPNAB_CORPUS")
        .env_remove("SKIP_CORPUS_HOOK")
        .output()?;

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
    Ok(())
}
