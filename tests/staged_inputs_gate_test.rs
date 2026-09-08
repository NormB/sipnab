//! A generated file must not be committed without the inputs it derives from.
//!
//! `main` broke four times in one session on one mistake wearing four faces:
//! `--features vcon` failing to compile because the pre-push matrix builds the
//! working tree; `docs/design/testing-matrix.md` losing seven flags to an
//! un-rebuilt binary, then gaining two that do not exist on `main` because it
//! WAS rebuilt, from a tree holding other agents' unfinished work; and
//! `EXPECTED_WIKI_LINKS` raised for documentation that never got committed.
//!
//! All four are `commit <subset of a dirty tree>` plus `generate from disk`.
//!
//! **The reason this needs a gate at STAGING time rather than a test.** After
//! the fact, no local check can see it: the working tree is self-consistent.
//! `coverage_matrix_test` passed on my machine both times it was wrong, because
//! my `cli.rs` and my matrix agreed with each other. Only CI, which checks out
//! the commit alone, disagreed. The question "does this artifact describe the
//! COMMIT" can only be asked of the index.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    repo().join("scripts/check-generated-inputs-staged.py")
}

fn run_in(dir: &Path) -> (i32, String) {
    // Scrubbed for the same reason `scrubbed_git` is, one layer further out.
    // The script under test shells out to git itself, so under `git commit`
    // it inherited the hook's `GIT_DIR` and `GIT_INDEX_FILE` and read the
    // REPOSITORY BEING COMMITTED TO instead of the fixture beside it. Four
    // tests here then reported on the real tree's staging: they passed when
    // the hook was run by hand, where those variables are unset, and failed
    // only under a real `git commit`. Scrubbing the child git was never
    // enough while the child PYTHON kept the variables and handed them on.
    let mut cmd = Command::new("python3");
    cmd.arg(script()).current_dir(dir);
    for var in HOOK_GIT_ENV {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("run check-generated-inputs-staged.py");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// A scratch repository with one generated artifact and one input.
///
/// A real fixture rather than a mocked git: the whole rule is about what `git
/// diff --cached` reports, and a fake index would test the fake.
struct Scratch(PathBuf);

/// A `git` that acts on the fixture and nothing else.
///
/// # The defect this exists for
///
/// Under `git commit` the pre-commit hook runs with `GIT_DIR`, `GIT_INDEX_FILE`
/// and `GIT_WORK_TREE` set for the repository being committed to, and a child
/// git inherits them: `git add` in a fixture directory then writes to the REAL
/// repository's index. A partial commit surfaced it — its temporary index is
/// where the fixture's staging went, and two tests here failed reading state
/// they had never written. The worktree gate in `repo_hygiene_test` had the
/// identical hole, found the same day.
fn scrubbed_git(dir: &std::path::Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir);
    for var in HOOK_GIT_ENV {
        c.env_remove(var);
    }
    c
}

/// The variables `git commit` exports to a hook, which any child that talks to
/// git will otherwise inherit.
///
/// One list, used by BOTH the fixture's `git` and the runner that spawns the
/// script under test. Two lists is how the second leak happened: the child git
/// was scrubbed, the child python was not, and it handed the variables on to a
/// git of its own.
const HOOK_GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_COMMON_DIR",
];

/// The scrub must actually be applied, or the fixtures write to the real repo.
#[test]
fn fixture_git_scrubs_the_hooks_environment() {
    let c = scrubbed_git(std::path::Path::new("."));
    let removed: Vec<&std::ffi::OsStr> = c
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k)
        .collect();
    for var in ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"] {
        assert!(
            removed.iter().any(|k| *k == var),
            "{var} not scrubbed: under `git commit`, a fixture's `git add` would stage \
             into the repository being committed to"
        );
    }
}

/// **First of two tests owed** for the commit that failed only under a real
/// `git commit`. The runner scrubs what the fixture's git scrubs.
///
/// `fixture_git_scrubs_the_hooks_environment` above proves the child GIT is
/// clean and proved nothing about the child PYTHON, which is the process that
/// actually reads the index in every test here.
#[test]
fn the_script_runner_scrubs_the_hooks_environment() {
    let mut cmd = Command::new("python3");
    cmd.arg(script()).current_dir(Path::new("."));
    for var in HOOK_GIT_ENV {
        cmd.env_remove(var);
    }
    let removed: Vec<&std::ffi::OsStr> = cmd
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k)
        .collect();
    for var in HOOK_GIT_ENV {
        assert!(
            removed.iter().any(|k| *k == *var),
            "{var} reaches the script under test; under `git commit` it would \
             then read the repository being committed to rather than the \
             fixture"
        );
    }
}

/// **Second of two.** Both children scrub the SAME list.
///
/// The leak was not a missing variable, it was a second list. Comparing the
/// two as sets is what stops the next variable from being added to one of them
/// and not the other — which fails, again, only under a real commit.
#[test]
fn every_child_that_talks_to_git_scrubs_the_same_variables() {
    let from_git: std::collections::BTreeSet<String> = scrubbed_git(Path::new("."))
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    let listed: std::collections::BTreeSet<String> =
        HOOK_GIT_ENV.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        from_git, listed,
        "the fixture's git scrubs a different set than HOOK_GIT_ENV names, so \
         the runner and the git no longer agree about what a hook exports"
    );
    assert!(
        listed.contains("GIT_INDEX_FILE"),
        "GIT_INDEX_FILE is the one a partial commit sets, and the one that \
         sent a fixture's staging into the real repository"
    );
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sipnab-staged-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("mkdir");
        let git = |args: &[&str]| {
            scrubbed_git(&dir).args(args).output().expect("git");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@example.invalid"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(dir.join("Cargo.toml"), "[package]\nversion = \"1\"\n").expect("w");
        std::fs::write(dir.join("Cargo.lock"), "sipnab 1\n").expect("w");
        git(&["add", "-A"]);
        git(&["commit", "-qm", "base"]);
        Self(dir)
    }
    fn git(&self, args: &[&str]) {
        scrubbed_git(&self.0).args(args).output().expect("git");
    }
    fn write(&self, rel: &str, body: &str) {
        std::fs::write(self.0.join(rel), body).expect("write");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 1. The real repository satisfies the rule.
#[test]
fn this_repository_stages_generated_files_with_their_inputs() {
    let (code, text) = run_in(&repo());
    assert!(
        code == 0 || code == 1,
        "the checker did not run cleanly (exit {code}):\n{text}"
    );
    if code == 1 {
        // Not a hard failure here: a developer mid-edit legitimately has a
        // dirty tree. The gate that BLOCKS is the pre-commit hook, which runs
        // against the index at the moment it matters.
        eprintln!("staged/unstaged mismatch present in the worktree:\n{text}");
    }
}

/// 2. Staging an artifact while its input stays behind is refused.
///
/// This is the exact shape of all four breakages.
#[test]
fn staging_a_generated_file_without_its_input_is_refused() {
    let s = Scratch::new("mismatch");
    s.write("Cargo.toml", "[package]\nversion = \"2\"\n");
    s.write("Cargo.lock", "sipnab 2\n");
    s.git(&["add", "Cargo.lock"]); // output staged, input left behind
    let (code, text) = run_in(&s.0);
    assert_eq!(
        code, 1,
        "staging Cargo.lock while Cargo.toml is modified and unstaged must be \
         refused; the committed lockfile would describe the worktree.\n{text}"
    );
    assert!(
        text.contains("Cargo.toml"),
        "the refusal must NAME the input left behind, or it cannot be acted \
         on:\n{text}"
    );
}

/// 3. Staging both together is accepted.
///
/// Without this the rule is satisfiable by refusing everything, which would
/// make the gate unusable and get it removed.
#[test]
fn staging_the_input_alongside_the_artifact_is_accepted() {
    let s = Scratch::new("together");
    s.write("Cargo.toml", "[package]\nversion = \"2\"\n");
    s.write("Cargo.lock", "sipnab 2\n");
    s.git(&["add", "Cargo.toml", "Cargo.lock"]);
    let (code, text) = run_in(&s.0);
    assert_eq!(
        code, 0,
        "input and artifact staged together must pass:\n{text}"
    );
}

/// 4. A dirty input with nothing staged is not the gate's business.
///
/// Ordinary mid-edit state. A gate that fired here would fire constantly and
/// get bypassed, which is how a real gate dies.
#[test]
fn a_dirty_worktree_with_an_empty_index_is_left_alone() {
    let s = Scratch::new("dirty");
    s.write("Cargo.toml", "[package]\nversion = \"2\"\n");
    let (code, text) = run_in(&s.0);
    assert_eq!(code, 0, "nothing staged means nothing to judge:\n{text}");
    assert!(text.contains("nothing staged"), "{text}");
}

/// 5. An UNTRACKED input counts.
///
/// The concurrent-agent case specifically: a brand-new module under `src/mcp/`
/// is an input to the testing matrix exactly as much as an edited one, and
/// `git diff --name-only` alone does not report it.
#[test]
fn an_untracked_input_is_treated_as_a_modified_one() {
    let s = Scratch::new("untracked");
    std::fs::create_dir_all(s.0.join("src/mcp")).expect("mkdir");
    std::fs::create_dir_all(s.0.join("docs/design")).expect("mkdir");
    s.write("src/mcp/brand_new.rs", "// a new module\n");
    s.write("docs/design/testing-matrix.md", "| flag |\n");
    s.git(&["add", "docs/design/testing-matrix.md"]);
    let (code, text) = run_in(&s.0);
    assert_eq!(
        code, 1,
        "a new untracked module under src/mcp/ is an input to the testing \
         matrix; leaving it unstaged means the committed matrix describes a \
         program the commit does not contain.\n{text}"
    );
    assert!(text.contains("brand_new.rs"), "{text}");
}

/// 6. Outside a git work tree it REFUSES rather than passing.
///
/// "Cannot answer" and "nothing wrong" must be different outcomes. A checker
/// that exits 0 when it cannot look is the failure this repository keeps
/// rediscovering.
#[test]
fn outside_a_work_tree_it_refuses_instead_of_passing() {
    let dir = std::env::temp_dir().join(format!("sipnab-nogit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (code, text) = run_in(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        code, 2,
        "outside a work tree the answer is 'cannot check', not 'clean':\n{text}"
    );
}

/// 7. The artifact map is not empty and names real paths.
///
/// A map that drifted to nothing would let every test above pass while the gate
/// examined no artifact at all.
#[test]
fn the_generated_artifact_map_names_paths_that_exist() {
    let body = std::fs::read_to_string(script()).expect("read the script");
    let start = body.find("DERIVED = {").expect("the DERIVED map");
    let end = body[start..].find("\n}").expect("map end") + start;
    let map = &body[start..end];
    let artifacts: Vec<&str> = map
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .collect();
    assert!(
        artifacts.len() >= 3,
        "only {} artifacts mapped; the gate is watching almost nothing: {artifacts:?}",
        artifacts.len()
    );
    for a in &artifacts {
        let p = repo().join(a);
        assert!(
            p.exists(),
            "DERIVED names `{a}`, which does not exist. A map entry pointing at \
             nothing silently protects nothing"
        );
    }
}

/// 8. `pre-commit` runs it.
///
/// The script only helps at staging time, and only if something invokes it
/// there. Unrun, it rots while the hook keeps printing OK for the rest.
#[test]
fn the_pre_commit_hook_runs_the_staged_inputs_check() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-commit"))
        .expect("read .githooks/pre-commit");
    assert!(
        hook.contains("scripts/check-generated-inputs-staged.py"),
        ".githooks/pre-commit does not run the staged-inputs check, so the rule \
         that would have caught four separate breakages is enforced by nothing"
    );
}

// ── The leak, as a rule over the whole test tree ────────────────────────
//
// Two tests owed for the four tests that read the wrong repository under
// `git commit`. The pair already here proves THIS file's two children are
// clean. Neither says anything about the other thirteen test files that spawn
// `git`, and the defect was never about this file — it was about a variable
// the hook exports that any child inherits.

/// Whether a test file that runs `git` inside its own fixture handles the
/// hook environment at all.
///
/// Two patterns are correct and this accepts both, because they are the same
/// decision made two ways:
///
/// * **Scrub it** — `env_remove("GIT_DIR")`, what this file's fixtures do.
///   The child then discovers the fixture the way an ordinary invocation
///   would.
/// * **Set it** — `.env("GIT_DIR", &fixture)`, what `corpus_push_gate_test`
///   does when it points the gate at a throwaway gitdir on purpose.
///
/// Inheriting is the third option and the only wrong one: under `git commit`
/// the child then acts on the repository being committed to, and every
/// assertion in the test is about state it never wrote.
fn handles_the_hook_environment(src: &str) -> bool {
    let scrubs = src.contains(r#"env_remove("GIT_DIR")"#)
        || src.contains(r#"env_remove(var)"#) && src.contains(r#""GIT_DIR""#);
    let sets = src.contains(r#".env("GIT_DIR""#);
    scrubs || sets
}

/// Whether a file builds a git repository of its own to run against.
///
/// The population at risk. A test that only asks the real repository
/// questions — `git ls-files`, `git status` — wants the repository the hook
/// points at, and inheriting is correct there.
fn builds_its_own_repository(src: &str) -> bool {
    let temp = src.contains("tempdir") || src.contains("temp_dir");
    let inits = src.contains(r#""init""#);
    temp && inits
}

/// **Ninth of ten tests owed for the five defects 0.5.159 uncovered.** Every
/// test that runs `git` in its own fixture accounts for the hook environment.
///
/// The rule the defect implies, over the tree rather than over one file.
/// Fifteen files in `tests/` spawn `git`; most of them ask the real repository
/// a question and should. The ones that build a repository of their own are
/// the ones a hook can hijack, and each of those has to have decided what to
/// do about it.
#[test]
fn every_test_that_runs_git_in_its_own_fixture_handles_the_hook_environment() {
    let dir = repo().join("tests");
    let mut at_risk = Vec::new();
    let mut careless = Vec::new();
    let mut scanned = 0usize;

    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().is_some_and(|e| e == "rs") {
                let src = std::fs::read_to_string(&p).unwrap_or_default();
                scanned += 1;
                if !src.contains(r#"Command::new("git")"#) {
                    continue;
                }
                if !builds_its_own_repository(&src) {
                    continue;
                }
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                at_risk.push(name.clone());
                if !handles_the_hook_environment(&src) {
                    careless.push(name);
                }
            }
        }
    }

    assert!(
        scanned > 40,
        "only {scanned} test file(s) were read; the walk is broken and this \
         gate covers nothing"
    );
    assert!(
        at_risk.len() >= 2,
        "only {at_risk:?} build a git repository of their own. Two did when \
         this was written -- this file and `corpus_push_gate_test` -- and a \
         shorter list means the detection stopped matching rather than that \
         the risk went away.\n\n\
         `repo_hygiene_test` scrubs the same variables and is deliberately NOT \
         in this population: it runs git in other WORKTREES, which are real \
         repositories rather than fixtures. Same variable, same fix, different \
         reason -- so counting it here would inflate the floor with a file \
         that would still pass if the fixture rule were deleted."
    );
    assert!(
        careless.is_empty(),
        "these test files build a git repository and inherit the hook's \
         environment into it: {careless:?}\nUnder `git commit`, GIT_DIR and \
         GIT_INDEX_FILE point at the repository being committed to, so the \
         child acts on that instead of the fixture — and the test passes \
         whenever the hook is run by hand, which is where those variables are \
         unset."
    );
}

/// **Tenth of ten.** The rule distinguishes the three cases.
///
/// A scan that reported nothing would be indistinguishable from one whose
/// substring checks stopped matching — and substring checks over source are
/// exactly the kind that rot silently when a helper is renamed. Both
/// predicates are driven directly, on all three shapes.
#[test]
fn the_hook_environment_rule_tells_the_three_cases_apart() {
    // Scrubbing, in both the direct and the list-driven spelling this tree
    // uses.
    assert!(handles_the_hook_environment(r#"c.env_remove("GIT_DIR");"#));
    assert!(handles_the_hook_environment(
        "const HOOK_GIT_ENV: &[&str] = &[\"GIT_DIR\"];\n cmd.env_remove(var);"
    ));
    // Setting it on purpose.
    assert!(handles_the_hook_environment(
        r#"cmd.env("GIT_DIR", &gitdir);"#
    ));
    // Inheriting: the one wrong answer.
    assert!(
        !handles_the_hook_environment(r#"Command::new("git").current_dir(&fixture).output()"#),
        "a spawn that neither scrubs nor sets must be reported"
    );

    // And the population filter: a fixture-building file is at risk, a file
    // that only questions the real repository is not.
    assert!(builds_its_own_repository(
        r#"let dir = std::env::temp_dir(); git(&["init", "-q"]);"#
    ));
    assert!(
        !builds_its_own_repository(r#"Command::new("git").args(["ls-files"]).current_dir(repo())"#),
        "a read-only question to the real repository is not at risk and must \
         not be demanded to scrub — the hook's repository is the one it wants"
    );

    // This file is itself in the at-risk population, which is what makes the
    // scan above non-vacuous.
    let own = std::fs::read_to_string(repo().join("tests/staged_inputs_gate_test.rs"))
        .expect("read this file");
    assert!(
        builds_its_own_repository(&own),
        "this file builds a fixture"
    );
    assert!(
        handles_the_hook_environment(&own),
        "and it must be its own first passing case"
    );
}
