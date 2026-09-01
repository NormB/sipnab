//! The feature-dependency check exists, runs clean, and the hook invokes it.
//!
//! `--features vcon` did not build at 0.5.130. `src/output/redact.rs` is gated
//! by `any(api, mcp, vcon)` and imports `hmac`, and only two of those three
//! features declared `dep:hmac`. `--features full` hid it, because `mcp`
//! supplies `hmac` anyway — so every ordinary build passed while one matrix
//! combination failed, and CI's `Features (vcon)` job is what found it.
//!
//! The pre-push feature matrix is supposed to catch exactly this, and did not.
//! It builds the WORKING TREE, and the working tree held the fix while the
//! commit lacked it. That is the defect worth gating: not a missing `hmac`,
//! but a check whose input is not the thing being shipped.
//!
//! These tests hold the replacement in place. A script nothing runs is a script
//! that rots, and the failure mode is silent — the hook keeps printing OK for
//! the gates it does run.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// 1. The tree currently satisfies the check.
///
/// Runs the real script rather than reimplementing its rule here. Two
/// implementations of one rule is two things to keep true, and the one that
/// drifts is whichever nobody reads.
#[test]
fn every_feature_declares_what_its_modules_import() {
    let out = Command::new("python3")
        .arg("scripts/check-feature-deps.py")
        .current_dir(repo())
        .output()
        .expect("run scripts/check-feature-deps.py");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "a feature-gated module imports a crate its feature does not declare. \
         A build enabling only that feature fails on the import, while \
         --features full passes because a sibling feature supplies the \
         crate:\n{stderr}{stdout}"
    );
    // Exit status alone cannot tell "nothing wrong" from "nothing examined".
    // The script refuses with status 2 when its walk goes blind, and this
    // pins the reported subject count so a silent narrowing shows up here.
    let scanned: usize = stdout
        .split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        scanned >= 20,
        "the check reported only {scanned} feature-gated modules; it is not \
         reaching src/ and a pass would mean nothing.\n{stdout}{stderr}"
    );
}

/// 2. `pre-commit` actually invokes it.
///
/// Without this the script can stay green in isolation forever while no gate
/// runs it, which is indistinguishable from a repository where the rule holds.
#[test]
fn the_pre_commit_hook_runs_the_feature_dependency_check() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-commit"))
        .expect("read .githooks/pre-commit");
    assert!(
        hook.contains("scripts/check-feature-deps.py"),
        ".githooks/pre-commit does not run scripts/check-feature-deps.py, so \
         the check that replaced a gate reading the wrong input is itself \
         never read"
    );
    assert!(
        hook.contains("exit 1"),
        "the hook must FAIL on the check rather than print and continue"
    );
}

/// 3. The script refuses rather than passes when it cannot see its subject.
///
/// This is the property that separates it from the gate it replaces. Status 2
/// means "cannot answer" and must not be confused with 0, "nothing wrong".
#[test]
fn the_check_refuses_when_it_can_see_nothing() {
    let script = std::fs::read_to_string(repo().join("scripts/check-feature-deps.py"))
        .expect("read scripts/check-feature-deps.py");
    assert!(
        script.contains("return 2"),
        "the script has no distinct 'cannot answer' status. Without one, a walk \
         that finds nothing exits 0 and reads as a clean tree — the exact shape \
         this repository keeps rediscovering"
    );
    assert!(
        script.contains("len(modules) < 10") && script.contains("len(optional) < 5"),
        "both floors must be present: one for the module walk and one for the \
         Cargo.toml dependency parse. Either going blind alone makes every \
         later comparison vacuous"
    );
}

/// 4. The script is executable and lives where the hook expects it.
#[test]
fn the_check_script_is_present_and_executable() {
    let path = repo().join("scripts/check-feature-deps.py");
    assert!(path.is_file(), "scripts/check-feature-deps.py is missing");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("stat the script")
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "scripts/check-feature-deps.py is not executable (mode {mode:o})"
        );
    }
    let _ = Path::new("");
}

// ── the rule itself, driven against fixture trees ───────────────────────
//
// `all(..)` and `any(..)` were read the same way until 2026-09-01: every
// feature named in the cfg had to supply the module's imports ON ITS OWN.
// That is right for `any` and wrong for `all`, where no build ever enables
// half the gate -- it demanded `vcon` declare `rmcp` to satisfy a build that
// cannot exist. Relaxing a gate is the moment to prove the half that catches
// things still catches them, so both readings are exercised here against
// trees built for the purpose rather than against this repository, whose
// current state can only ever demonstrate one of them.

/// A throwaway crate tree the script can be pointed at.
///
/// Cleared up by the caller in the same test that makes it, and built under
/// `CARGO_TARGET_TMPDIR` so a crash leaves nothing outside `target/`.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    /// A tree whose one interesting module sits behind `gate` and imports a
    /// crate only feature `a` declares.
    ///
    /// Padded to clear the script's own anti-vacuity floors: it refuses with
    /// status 2 below ten gated modules or five optional crates, and a
    /// refusal must not be mistaken here for the verdict under test.
    fn new(name: &str, gate: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create fixture src");

        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n\n[dependencies]\n\
             alpha = { version = \"1\", optional = true }\n\
             beta = { version = \"1\", optional = true }\n\
             gamma = { version = \"1\", optional = true }\n\
             delta = { version = \"1\", optional = true }\n\
             epsilon = { version = \"1\", optional = true }\n\
             zeta = { version = \"1\", optional = true }\n\n\
             [features]\n\
             a = [\"dep:alpha\"]\n\
             b = [\"dep:beta\"]\n\
             filler = [\"dep:gamma\"]\n",
        )
        .expect("write fixture Cargo.toml");

        // The subject: gated by `gate`, importing a crate only `a` supplies.
        let subject = src.join("subject");
        std::fs::create_dir_all(&subject).expect("create subject");
        std::fs::write(
            subject.join("mod.rs"),
            format!("#[cfg({gate})]\npub mod thing;\n"),
        )
        .expect("write subject mod.rs");
        std::fs::write(subject.join("thing.rs"), "use alpha::Thing;\n").expect("write thing.rs");

        // Padding: gated, clean, and enough of it to clear the floor.
        for i in 0..11 {
            let d = src.join(format!("pad{i}"));
            std::fs::create_dir_all(&d).expect("create pad");
            std::fs::write(
                d.join("mod.rs"),
                "#[cfg(feature = \"filler\")]\npub mod m;\n",
            )
            .expect("write pad mod.rs");
            std::fs::write(d.join("m.rs"), "use gamma::X;\n").expect("write pad m.rs");
        }

        Self { root }
    }

    /// The script's exit status against this tree, and what it said.
    fn verdict(&self) -> (i32, String) {
        let out = Command::new("python3")
            .arg(repo().join("scripts/check-feature-deps.py"))
            .arg(&self.root)
            .current_dir(repo())
            .output()
            .expect("run scripts/check-feature-deps.py");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code().unwrap_or(-1), said)
    }

    fn discard(self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `any(a, b)` still requires each alternative to stand on its own.
///
/// The 0.5.130 bug exactly: a build enabling only `b` compiles the file and
/// fails on an import `a` was supplying. If relaxing `all` had relaxed this
/// too, the gate would pass the very defect it was written for.
#[test]
fn an_any_gate_still_requires_each_alternative_to_stand_alone() {
    let fixture = Fixture::new("any_gate", "any(feature = \"a\", feature = \"b\")");
    let (code, said) = fixture.verdict();
    fixture.discard();

    assert_eq!(
        code, 1,
        "a module gated any(a, b) that imports a crate only `a` declares must \
         be reported: a build with only `b` fails on the import. Got:\n{said}"
    );
    assert!(
        said.contains("alpha") && said.contains('b'),
        "the report must name the crate and the feature that lacks it:\n{said}"
    );
}

/// `all(a, b)` is satisfied by the two features together.
///
/// The correction. Every build compiling this file has both features, so
/// requiring `b` to declare what `a` supplies describes no build that exists.
#[test]
fn an_all_gate_is_satisfied_by_the_two_features_together() {
    let fixture = Fixture::new("all_gate", "all(feature = \"a\", feature = \"b\")");
    let (code, said) = fixture.verdict();
    fixture.discard();

    assert_eq!(
        code, 0,
        "a module gated all(a, b) is compiled only when BOTH are on, so `a` \
         supplying the import is enough. Got:\n{said}"
    );
}

/// A gate mixing the two falls back to the strict reading.
///
/// `any(all(a, b), c)` is a shape the parser does not model. The safe answer
/// to "I do not understand this" is the strict one; a parser that guesses
/// permissively when confused is a gate that opens as soon as it stops
/// recognizing what it reads.
#[test]
fn a_cfg_the_parser_does_not_model_is_read_strictly() {
    let fixture = Fixture::new(
        "mixed_gate",
        "any(all(feature = \"a\", feature = \"b\"), feature = \"filler\")",
    );
    let (code, said) = fixture.verdict();
    fixture.discard();

    assert_eq!(
        code, 1,
        "a cfg the parser cannot model must be read strictly, not waved \
         through. Got:\n{said}"
    );
}

/// The fixtures clear the script's floors, so a verdict is a verdict.
///
/// Without this, a fixture too small makes the script refuse with status 2 --
/// and a test asserting "not zero" would read that refusal as the failure it
/// was looking for, passing for a reason that has nothing to do with the rule.
#[test]
fn the_fixtures_are_large_enough_for_the_script_to_answer() {
    let fixture = Fixture::new("floor_check", "any(feature = \"a\", feature = \"b\")");
    let (code, said) = fixture.verdict();
    fixture.discard();

    assert_ne!(
        code, 2,
        "the script refused rather than answered; the fixture is below its \
         anti-vacuity floors:\n{said}"
    );
    assert!(
        said.contains("checked 12 feature-gated modules"),
        "the fixture should present 12 gated modules; if it does not, the \
         walk is not seeing what these tests think it is:\n{said}"
    );
}
