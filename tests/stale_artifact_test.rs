// SPDX-License-Identifier: MIT OR Apache-2.0

//! A measurement must name the binary that produced it.
//!
//! The incident this gates, in full. A run needed to know whether sipnab's MCP
//! tools fence untrusted capture text in `⟦untrusted-capture-data⟧` markers, so
//! it used the repository's own helper, `demos/mcp-stdio.sh`. That script
//! invoked a bare `sipnab`, which is PATH resolution. On the box in question
//! PATH resolved to `/usr/local/sbin/sipnab` -- a packaged **0.5.78**, fifty-five
//! releases behind the working tree. 0.5.78 has no fencing. The run therefore
//! observed no fencing, concluded the documented claim was FALSE, and reported
//! it. Re-running the identical command as
//! `PATH="$PWD/target/debug:$PATH" demos/mcp-stdio.sh ...` showed the fencing
//! present the whole time. The finding was wrong and had to be retracted.
//!
//! Nothing about that run failed. The script worked, the server answered, the
//! JSON parsed. The only broken thing was the unstated premise that the binary
//! answering was the binary under test -- and an unstated premise cannot be
//! checked by whoever is reading the answer.
//!
//! The property these tests pin is therefore not "everyone must install
//! sipnab", nor "the PATH copy must match the tree". It is narrower and
//! enforceable:
//!
//! 1. A helper that shells out must offer a way to say WHICH binary
//!    (`SIPNAB_BIN`), so a measurement can be pinned to the tree under test.
//! 2. A Rust test must reach the freshly built binary through
//!    `env!("CARGO_BIN_EXE_sipnab")` and never through PATH.
//! 3. Divergence between PATH and the tree is REPORTED rather than punished --
//!    a developer with an older sipnab installed is not doing anything wrong,
//!    but a run that cannot tell the two apart is.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Repository root, as cargo knows it.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The version string `Cargo.toml` declares for the `sipnab` package.
///
/// Reads the `[package]` section only: the workspace preamble and the
/// dependency tables also contain `version = "..."` lines, and taking the
/// first match in the file would pick up whichever one moved.
fn cargo_toml_version() -> String {
    let path = repo_root().join("Cargo.toml");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if in_package && let Some(rest) = trimmed.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                return rest.trim().trim_matches('"').to_string();
            }
        }
    }
    panic!(
        "no `version = \"...\"` under [package] in {} -- every gate in this file \
         compares against that value, so it cannot be allowed to go missing",
        path.display()
    );
}

/// The semver triple in a `sipnab --version` line.
///
/// The line looks like `sipnab 0.5.134 (ef843d86-dirty) features: native,...`,
/// so this takes the first `MAJOR.MINOR.PATCH` and ignores the build metadata
/// and feature list that follow.
fn parse_version(output: &str) -> Option<String> {
    let re = regex::Regex::new(r"\bsipnab\s+(\d+\.\d+\.\d+)").expect("static regex must compile");
    re.captures(output).map(|c| {
        c.get(1)
            .expect("group 1 is not optional")
            .as_str()
            .to_string()
    })
}

/// Run `<bin> --version` and return its combined stdout, or `None` if the
/// binary could not be executed at all.
fn version_output(bin: &Path) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Every `sipnab` on PATH, in PATH order, first entry first.
fn sipnab_on_path() -> Vec<PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    std::env::split_paths(&path)
        .map(|dir| dir.join("sipnab"))
        .filter(|candidate| candidate.is_file())
        .collect()
}

/// Read a file under the repository root, panicking with its path on failure.
fn read_repo_file(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `demos/mcp-stdio.sh` must let the caller name the binary it drives.
///
/// This is the exact script that produced the wrong 0.5.78 answer. It used to
/// invoke a bare `sipnab`; it now defaults `SIPNAB_BIN` to `sipnab` and runs
/// `"$SIPNAB_BIN"`, which keeps the no-argument behavior identical while
/// giving a caller who cares a way to pin the measurement to this tree.
///
/// Lose this and the helper silently answers from whatever PATH found, which
/// is the whole incident: a run that cannot state which binary spoke cannot
/// have its conclusion checked by anyone, including its author.
#[test]
fn mcp_stdio_helper_lets_the_caller_name_the_binary() {
    let rel = "demos/mcp-stdio.sh";
    let text = read_repo_file(rel);

    assert!(
        text.contains(r#"SIPNAB_BIN="${SIPNAB_BIN:-sipnab}""#),
        "{rel} must default the binary with `SIPNAB_BIN=\"${{SIPNAB_BIN:-sipnab}}\"` so an \
         explicit override is possible and the unset case still resolves from PATH as before. \
         demos/gen-mcp-examples.sh and demos/Makefile already use the SIPNAB_BIN name; this \
         script is the one that did not, and it is the one that answered from 0.5.78."
    );

    assert!(
        text.contains(r#""$SIPNAB_BIN" --mcp"#),
        "{rel} must launch the server as `\"$SIPNAB_BIN\" --mcp`, not as a bare `sipnab --mcp`. \
         Declaring SIPNAB_BIN and then invoking `sipnab` anyway is worse than not declaring it: \
         the override looks honored and is not."
    );

    let bare = regex::Regex::new(r"(?m)^\s*(?:coproc\s+\w+\s*\{\s*)?sipnab\s")
        .expect("static regex must compile");
    assert!(
        !bare.is_match(&text),
        "{rel} still invokes a bare `sipnab` at the start of a command: {:?}. Every invocation \
         must go through \"$SIPNAB_BIN\".",
        bare.find(&text).map(|m| m.as_str())
    );

    // The mechanism is only half of it. A reader who does not know why the
    // override exists will drop it the next time the script is touched, so the
    // script has to carry the reason, with the version that made it concrete.
    assert!(
        text.contains("0.5.78"),
        "{rel} must name 0.5.78 in its header comment. The override is not self-explanatory: \
         without the incident written down, `SIPNAB_BIN` reads like ceremony and gets removed."
    );
    assert!(
        text.contains("PATH"),
        "{rel} must explain in prose that the default is PATH resolution. The hazard is the \
         DEFAULT, not the override."
    );
}

/// A `sipnab` on PATH is reported, never required and never compared for equality.
///
/// Deliberately asymmetric. It is entirely reasonable for a developer to have
/// an older packaged sipnab installed -- 0.5.78 in the incident -- and this
/// test must not fail them for it, nor demand that anyone install one. What it
/// refuses is the combination that actually caused the retraction: a PATH
/// binary exists AND the repository offers no way to say "not that one".
///
/// The divergence itself is printed, so `cargo test -- --nocapture` on the box
/// where a finding looks strange states, in one line, which binary PATH would
/// have answered with.
#[test]
fn a_path_sipnab_is_visible_and_overridable() {
    let tree = cargo_toml_version();
    let found = sipnab_on_path();

    if found.is_empty() {
        println!("no `sipnab` on PATH; tree builds {tree}");
        return;
    }

    for bin in &found {
        match version_output(bin).as_deref().and_then(parse_version) {
            Some(v) if v == tree => {
                println!("PATH {}: {v} (same as tree)", bin.display());
            }
            Some(v) => {
                println!(
                    "PATH {}: {v} -- tree builds {tree}. NOT a failure. It is the reason every \
                     measurement in this repository must name its binary.",
                    bin.display()
                );
            }
            None => {
                println!(
                    "PATH {}: `--version` unparseable; treat any measurement from it as \
                     unattributed",
                    bin.display()
                );
            }
        }
    }

    // The override mechanism the presence of a PATH binary makes mandatory.
    let script = read_repo_file("demos/mcp-stdio.sh");
    assert!(
        script.contains("SIPNAB_BIN"),
        "a `sipnab` exists on PATH ({}) but demos/mcp-stdio.sh has no SIPNAB_BIN override, so \
         there is no way to run it against this tree. That is exactly the state the repository \
         was in when a 0.5.78 answer was reported as a finding about {tree}.",
        found[0].display()
    );

    let makefile = read_repo_file("demos/Makefile");
    assert!(
        makefile.contains("SIPNAB_BIN"),
        "a `sipnab` exists on PATH ({}) but demos/Makefile does not pin SIPNAB_BIN, so a \
         published render could come from it rather than from this tree.",
        found[0].display()
    );
}

/// The positive control: `env!("CARGO_BIN_EXE_sipnab")` is the tree's binary.
///
/// This is the in-test way to reach the right program, and the reason the
/// scan below can insist on it. Cargo rebuilds this path from the current
/// source before the test runs, so its `--version` agreeing with `Cargo.toml`
/// is what makes "use CARGO_BIN_EXE" a real answer rather than a slogan.
///
/// If this ever fails, every other binary-touching test in the suite is
/// suspect, because they all reach the program the same way.
#[test]
fn cargo_bin_exe_is_the_binary_this_tree_builds() {
    let bin = Path::new(env!("CARGO_BIN_EXE_sipnab"));

    assert!(
        bin.is_file(),
        "CARGO_BIN_EXE_sipnab points at {}, which is not a file. Cargo is supposed to build it \
         before this test runs.",
        bin.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(bin)
            .unwrap_or_else(|e| panic!("stat {}: {e}", bin.display()))
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "{} is not executable (mode {mode:o}); a measurement cannot come from a binary that \
             cannot run",
            bin.display()
        );
    }

    let out =
        version_output(bin).unwrap_or_else(|| panic!("could not run {} --version", bin.display()));
    let got = parse_version(&out).unwrap_or_else(|| {
        panic!(
            "no `sipnab MAJOR.MINOR.PATCH` in `{} --version` output: {out:?}. Every attribution \
             in this repository -- demos/gen-mcp-examples.sh included -- reads the version out \
             of this line.",
            bin.display()
        )
    });
    let want = cargo_toml_version();

    assert_eq!(
        got,
        want,
        "{} reports {got} but Cargo.toml declares {want}. The freshly built binary must be the \
         one this tree describes, or CARGO_BIN_EXE_sipnab is no safer than PATH.",
        bin.display()
    );
}

/// No integration test may reach sipnab through PATH.
///
/// `Command::new("sipnab")` in a test is the incident with a green checkmark on
/// it: on a machine with no sipnab installed the test errors out and someone
/// notices, but on a machine with an OLD one installed it passes, or fails, for
/// reasons that have nothing to do with the change under test.
///
/// Reports every offender by path, because the fix is per-call-site and a
/// count would not say where.
#[test]
fn no_test_reaches_sipnab_through_path() {
    let dir = repo_root().join("tests");
    let bare = regex::Regex::new(r#"Command::new\(\s*"sipnab"\s*\)"#).expect("static regex");

    let mut scanned = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("walk {}: {e}", dir.display()))
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        scanned += 1;
        // This file quotes the forbidden pattern inside its own regex literal;
        // matching itself would make the gate unfixable.
        if path.file_name().and_then(|n| n.to_str()) == Some("stale_artifact_test.rs") {
            continue;
        }
        if bare.is_match(&text) {
            offenders.push(path.display().to_string());
        }
    }

    assert!(
        scanned > 1,
        "scanned only {scanned} file(s) under {} -- a scan that reads nothing reports nothing, \
         and would keep passing after the whole suite moved",
        dir.display()
    );
    assert!(
        offenders.is_empty(),
        "these tests invoke a bare `sipnab` from PATH instead of \
         env!(\"CARGO_BIN_EXE_sipnab\"): {}. On a box with an older packaged sipnab they measure \
         that one, and say so nowhere.",
        offenders.join(", ")
    );
}

/// The demo scripts that execute sipnab are enumerable, and there is at least one.
///
/// The scan above has teeth only because something enumerates the shell side
/// too; a demo script is exactly as capable of publishing a stale answer as a
/// test is, and `demos/gen-mcp-examples.sh --check` writes its output onto the
/// homepage. The non-emptiness assertion is the point: an enumeration that
/// finds nothing passes forever, including after the pattern it looks for has
/// been renamed out from under it.
///
/// Scripts that only talk to an already-running server (`demos/mcp-call.sh`
/// drives the docker harness over HTTP) execute no binary and are correctly
/// absent from the list.
#[test]
fn demo_scripts_that_execute_sipnab_are_enumerated_and_pinned() {
    let dir = repo_root().join("demos");
    // Either an explicit override, or a bare command invocation at the head of
    // a line -- the shape `demos/mcp-stdio.sh` had before it was fixed.
    let runs = regex::Regex::new(r"(?m)SIPNAB_BIN|^\s*(?:coproc\s+\w+\s*\{\s*)?sipnab\s+-")
        .expect("static regex");

    let mut shell_scripts = 0usize;
    let mut runners: Vec<(String, String)> = Vec::new();

    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("walk {}: {e}", dir.display()))
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("sh") {
            continue;
        }
        shell_scripts += 1;
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if runs.is_match(&text) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("dir entry has a name")
                .to_string();
            runners.push((name, text));
        }
    }

    assert!(
        shell_scripts > 0,
        "no *.sh under {} -- the demo helpers moved, and this gate has been scanning an empty \
         set ever since",
        dir.display()
    );
    assert!(
        !runners.is_empty(),
        "found {shell_scripts} shell script(s) under {} but none that executes sipnab. Either \
         the helpers stopped running the binary, or the pattern this gate looks for no longer \
         matches how they do it -- and a vacuous scan is indistinguishable from a clean one.",
        dir.display()
    );

    // Mentioning SIPNAB_BIN is not honoring it. The check is that no
    // enumerated script still starts a command with a bare `sipnab`, because a
    // script can declare the override in a comment and then resolve from PATH
    // anyway -- which reads as fixed and is not.
    let bare = regex::Regex::new(r"(?m)^\s*(?:coproc\s+\w+\s*\{\s*)?sipnab\s+-")
        .expect("static regex must compile");
    let unpinned: Vec<&str> = runners
        .iter()
        .filter(|(_, text)| !text.contains("SIPNAB_BIN") || bare.is_match(text))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        unpinned.is_empty(),
        "demos/{unpinned:?} execute sipnab without honoring SIPNAB_BIN -- either the variable \
         is absent, or it is declared and then bypassed by a bare `sipnab` invocation -- so a \
         caller cannot point them at this tree. demos/gen-mcp-examples.sh and demos/Makefile set \
         the convention; demos/mcp-stdio.sh is the one that ignored it and answered from 0.5.78."
    );
}

/// Self-check: the version parser this file relies on actually parses.
///
/// Every attribution above -- the PATH report, the Cargo.toml comparison --
/// is only as good as `parse_version`. A parser that silently returns `None`,
/// or that returns an empty string, would let
/// `cargo_bin_exe_is_the_binary_this_tree_builds` compare nothing against
/// nothing and pass. So this pins the parser against a real `--version` line
/// from the freshly built binary, and against the shapes it must reject.
#[test]
fn the_parsed_version_is_a_non_empty_semver_triple() {
    let bin = Path::new(env!("CARGO_BIN_EXE_sipnab"));
    let out =
        version_output(bin).unwrap_or_else(|| panic!("could not run {} --version", bin.display()));

    let v = parse_version(&out).unwrap_or_else(|| {
        panic!(
            "`{} --version` produced no parseable version: {out:?}",
            bin.display()
        )
    });

    assert!(!v.is_empty(), "parsed version from {out:?} is empty");

    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "parsed version {v:?} is not a MAJOR.MINOR.PATCH triple; the comparisons in this file \
         assume three components"
    );
    for (i, part) in parts.iter().enumerate() {
        assert!(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "component {i} of {v:?} is {part:?}, which is not a decimal number"
        );
    }

    // The parser must not invent a version out of prose that merely mentions
    // the program, or accept a two-component string. Without these it could
    // "succeed" against any text at all, and its callers would compare
    // whatever it returned.
    assert_eq!(
        parse_version("sipnab 1.2.3 (abc) features: native"),
        Some("1.2.3".to_string()),
        "parser must take the triple from a normal --version line"
    );
    assert_eq!(
        parse_version("sipnab is a SIP capture tool"),
        None,
        "parser must not report a version for text that carries none"
    );
    assert_eq!(
        parse_version("sipnab 0.5"),
        None,
        "parser must reject a two-component version rather than pad it"
    );
}
