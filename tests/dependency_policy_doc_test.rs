// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The "Dependencies" section of `CONTRIBUTING.md` must keep telling the truth.
//!
//! OpenSSF Baseline control DO-06.01 asks for a documented way to choose a new
//! dependency and to track the ones already in use. The tooling existed before
//! the document did; the section is the policy a contributor reads. A policy
//! page that names a tool the repository no longer runs is worse than no page,
//! because it tells a reviewer something is checked when nothing is.
//!
//! So every tool, file and schedule the section names is checked here against
//! the file that actually wires it: `deny.toml`, the tracked lockfiles,
//! `.github/dependabot.yml`, and the two workflows that run the scanners.

use std::path::Path;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    let p = repo().join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// The body of `## Dependencies` in CONTRIBUTING.md, up to the next `## `.
fn section() -> Result<String, TestError> {
    let guide = read("CONTRIBUTING.md")?;
    let start = guide
        .lines()
        .position(|l| l.trim_end() == "## Dependencies")
        .ok_or(
            "CONTRIBUTING.md has no `## Dependencies` section: OpenSSF Baseline \
             DO-06.01 needs a written policy for choosing and tracking crates",
        )?;
    Ok(guide
        .lines()
        .skip(start + 1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Every file the section cites is linked, and the link target exists.
#[test]
fn section_links_every_file_it_relies_on() -> Result<(), TestError> {
    let s = section()?;
    for f in [
        "deny.toml",
        "Cargo.lock",
        "fuzz/Cargo.lock",
        ".github/dependabot.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/osv-scanner.yml",
        "osv-scanner.toml",
    ] {
        assert!(
            s.contains(&format!("]({f})")),
            "the Dependencies section must link `{f}` so a reader can check the claim"
        );
        assert!(
            repo().join(f).is_file(),
            "the section cites {f}, which is gone"
        );
    }
    Ok(())
}

/// License rule: the section says licenses are checked against `deny.toml`,
/// so `deny.toml` must have an allow list, and the project license the section
/// quotes must be the one in Cargo.toml.
#[test]
fn license_rule_is_enforced_by_deny_toml() -> Result<(), TestError> {
    let s = section()?;
    assert!(
        s.contains("cargo deny check"),
        "the section must name `cargo deny check`"
    );
    assert!(
        s.contains("MIT OR Apache-2.0"),
        "the section must state the project license"
    );
    assert!(
        read("Cargo.toml")?.contains("license = \"MIT OR Apache-2.0\""),
        "the section states MIT OR Apache-2.0; Cargo.toml disagrees"
    );
    let deny = read("deny.toml")?;
    let licenses = deny
        .split("\n[licenses]\n")
        .nth(1)
        .ok_or("deny.toml has no [licenses] section, but the section says licenses are checked")?;
    assert!(
        licenses.contains("allow = ["),
        "deny.toml [licenses] has no allow list"
    );
    for l in ["\"MIT\"", "\"Apache-2.0\""] {
        assert!(licenses.contains(l), "deny.toml does not allow {l}");
    }
    Ok(())
}

/// Source rule: the section says crates come from crates.io only and a git
/// fork cannot be pulled in. That is `[sources]` in deny.toml, plus the
/// absence of a `[patch]` override that would swap a crate for a fork.
#[test]
fn crates_io_only_rule_is_enforced() -> Result<(), TestError> {
    let s = section()?;
    assert!(
        s.contains("crates.io"),
        "the section must say crates come from crates.io"
    );
    let deny = read("deny.toml")?;
    assert!(
        deny.contains("unknown-git = \"deny\""),
        "deny.toml no longer rejects git sources"
    );
    assert!(
        deny.contains("unknown-registry = \"deny\""),
        "deny.toml no longer rejects other registries"
    );
    for manifest in ["Cargo.toml", "fuzz/Cargo.toml"] {
        assert!(
            !read(manifest)?.contains("[patch"),
            "{manifest} has a [patch] override; the section says forks are not used"
        );
    }
    Ok(())
}

/// The section tells contributors to turn off default features. That must
/// be what Cargo.toml actually does, or the advice is invented.
#[test]
fn default_features_advice_matches_cargo_toml() -> Result<(), TestError> {
    assert!(section()?.contains("default-features = false"));
    assert!(
        read("Cargo.toml")?.contains("default-features = false"),
        "no dependency in Cargo.toml turns default features off"
    );
    Ok(())
}

/// Both lockfiles are committed: tracked by git, not merely present on disk.
#[test]
fn lockfiles_are_tracked() -> Result<(), TestError> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "--error-unmatch",
            "Cargo.lock",
            "fuzz/Cargo.lock",
        ])
        .current_dir(repo())
        .output()?;
    assert!(
        out.status.success(),
        "a lockfile the Dependencies section calls committed is not tracked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// Dependabot watches both cargo workspaces weekly, as the section says.
#[test]
fn dependabot_watches_both_cargo_workspaces_weekly() -> Result<(), TestError> {
    let s = section()?;
    assert!(s.contains("Dependabot") && s.contains("weekly"));
    let cfg = read(".github/dependabot.yml")?;
    // One entry lists both directories, so both lock files move in one pull
    // request; tests/dependabot_cargo_layout_test.rs holds the entry's shape.
    let both = cfg
        .split("- package-ecosystem:")
        .skip(1)
        .find(|b| {
            b.trim_start().starts_with("\"cargo\"")
                && b.lines().any(|l| l.trim() == "- \"/\"")
                && b.lines().any(|l| l.trim() == "- \"/fuzz\"")
        })
        .ok_or("dependabot.yml has no cargo entry that lists both `/` and `/fuzz`")?;
    assert!(
        both.contains("interval: \"weekly\""),
        "the cargo entry for both lock files is not weekly"
    );
    assert!(
        s.contains("one pull request for both lock files"),
        "the section does not say that both lock files move in one pull request"
    );
    Ok(())
}

/// Every command the section tells a contributor to run is the command CI
/// runs, so running it locally reproduces the gate rather than an
/// approximation of it.
#[test]
fn local_commands_are_the_ci_commands() -> Result<(), TestError> {
    let s = section()?;
    let ci = read(".github/workflows/ci.yml")?;
    let cmds = [
        "cargo audit --ignore RUSTSEC-2023-0071",
        "cargo audit --file fuzz/Cargo.lock --ignore RUSTSEC-2023-0071",
        "cargo deny check",
    ];
    for c in cmds {
        assert!(
            s.contains(c),
            "the section must tell a contributor to run `{c}`"
        );
        assert!(
            ci.lines().any(|l| l.trim() == format!("run: {c}")),
            "the section tells contributors to run `{c}`, but ci.yml does not run it"
        );
    }
    // Both run on pull requests to main, which is when a new crate arrives.
    assert!(ci.contains("pull_request:\n    branches: [main]"));
    Ok(())
}

/// OSV-Scanner: the workflow really invokes the scanner over both lockfiles,
/// on pull requests and on the weekly schedule the section describes.
#[test]
fn osv_scanner_is_wired_as_described() -> Result<(), TestError> {
    let s = section()?;
    assert!(s.contains("OSV-Scanner") && s.contains("Wednesday"));
    let wf = read(".github/workflows/osv-scanner.yml")?;
    assert!(
        wf.contains("uses: google/osv-scanner-action/"),
        "osv-scanner.yml no longer runs the scanner"
    );
    for lock in ["--lockfile=./Cargo.lock", "--lockfile=./fuzz/Cargo.lock"] {
        assert!(wf.contains(lock), "osv-scanner.yml no longer scans {lock}");
    }
    assert!(
        wf.contains("pull_request:"),
        "osv-scanner.yml no longer runs on pull requests"
    );
    assert!(
        wf.contains("- cron: '41 5 * * 3'"),
        "the section says Wednesdays; the osv-scanner.yml schedule changed"
    );
    Ok(())
}

// ── cargo deny reads every feature (DENY-CHECKS-DEFAULT-FEATURES-ONLY) ────
//
// `cargo deny check` read the default features: 240 crates of the 380 that
// `--all-features` resolves (cargo-deny 0.20.2, 2026-11-12). The license,
// ban, source and advisory rules never saw a crate that only an optional
// feature brings in. The rule is in `deny.toml`, `[graph] all-features`, so
// every run reads it: CI, a contributor's shell, a script.

/// Whether a line that runs `cargo deny` narrows the features it reads, or
/// reads a configuration other than `deny.toml`.
fn narrows_cargo_deny(line: &str) -> bool {
    let code = line.trim();
    code.contains("cargo deny")
        && [
            "--no-default-features",
            "--features",
            "--config",
            "--exclude",
        ]
        .iter()
        .any(|flag| code.contains(flag))
}

/// `deny.toml` tells cargo-deny to read every feature.
#[test]
fn deny_toml_reads_every_feature() -> Result<(), TestError> {
    let config: toml::Table = read("deny.toml")?.parse()?;
    let graph = config
        .get("graph")
        .and_then(toml::Value::as_table)
        .ok_or("deny.toml has no [graph] table: cargo deny reads the default features only")?;
    assert_eq!(
        graph.get("all-features").and_then(toml::Value::as_bool),
        Some(true),
        "deny.toml [graph] all-features must be true"
    );
    assert_eq!(
        graph
            .get("no-default-features")
            .and_then(toml::Value::as_bool),
        None,
        "deny.toml [graph] must not drop the default features"
    );
    assert!(
        !graph.contains_key("features") && !graph.contains_key("exclude"),
        "deny.toml [graph] must not name a feature list or exclude a crate"
    );
    Ok(())
}

/// No workflow, hook, script or contributor command narrows what
/// `cargo deny` reads, and at least one workflow runs it.
#[test]
fn no_cargo_deny_run_narrows_the_features() -> Result<(), TestError> {
    let mut files = vec![repo().join("CONTRIBUTING.md")];
    for dir in [".github/workflows", ".githooks", "scripts"] {
        for entry in std::fs::read_dir(repo().join(dir))? {
            let path = entry?.path();
            if path.is_file() {
                files.push(path);
            }
        }
    }
    let mut runs = 0usize;
    let mut narrowed = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let workflow = path.extension().is_some_and(|e| e == "yml");
        for (i, line) in text.lines().enumerate() {
            if workflow && line.trim_start().starts_with("run: cargo deny") {
                runs += 1;
            }
            if narrows_cargo_deny(line) {
                let name = path.strip_prefix(repo()).unwrap_or(path).display();
                narrowed.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        runs >= 1,
        "no workflow step runs cargo deny: the scan stopped matching"
    );
    assert!(
        narrowed.is_empty(),
        "these cargo deny runs do not read every feature through deny.toml:\n{}",
        narrowed.join("\n")
    );
    Ok(())
}

/// The predicate: a plain run and one that adds `--all-features` are whole;
/// a feature list, no default features, another configuration or an
/// excluded crate is not; a line that does not run cargo deny is not judged.
#[test]
fn the_narrowing_predicate_knows_each_narrowing_flag() {
    for whole in [
        "run: cargo deny check",
        "cargo deny --all-features check",
        "        run: cargo deny check licenses",
        "cargo test --no-default-features --features native",
        "",
    ] {
        assert!(!narrows_cargo_deny(whole), "{whole:?} reads every feature");
    }
    for narrowed in [
        "run: cargo deny --no-default-features check",
        "cargo deny --features full check",
        "cargo deny check --config other.toml",
        "cargo deny --exclude rsa check",
    ] {
        assert!(
            narrows_cargo_deny(narrowed),
            "{narrowed:?} narrows the check"
        );
    }
}

/// The contributor section says that the check reads every feature.
#[test]
fn the_section_says_cargo_deny_reads_every_feature() -> Result<(), TestError> {
    let s = section()?;
    assert!(
        s.contains("every feature"),
        "the section must say that `cargo deny check` reads every feature"
    );
    assert!(
        s.contains("`[graph]`"),
        "the section must name the `[graph]` table of deny.toml"
    );
    Ok(())
}
