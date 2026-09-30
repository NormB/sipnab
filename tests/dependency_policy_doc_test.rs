// SPDX-License-Identifier: MIT OR Apache-2.0

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

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The body of `## Dependencies` in CONTRIBUTING.md, up to the next `## `.
fn section() -> String {
    let guide = read("CONTRIBUTING.md");
    let start = guide
        .lines()
        .position(|l| l.trim_end() == "## Dependencies")
        .expect(
            "CONTRIBUTING.md has no `## Dependencies` section: OpenSSF Baseline \
             DO-06.01 needs a written policy for choosing and tracking crates",
        );
    guide
        .lines()
        .skip(start + 1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every file the section cites is linked, and the link target exists.
#[test]
fn section_links_every_file_it_relies_on() {
    let s = section();
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
}

/// License rule: the section says licenses are checked against `deny.toml`,
/// so `deny.toml` must have an allow list, and the project license the section
/// quotes must be the one in Cargo.toml.
#[test]
fn license_rule_is_enforced_by_deny_toml() {
    let s = section();
    assert!(
        s.contains("cargo deny check"),
        "the section must name `cargo deny check`"
    );
    assert!(
        s.contains("MIT OR Apache-2.0"),
        "the section must state the project license"
    );
    assert!(
        read("Cargo.toml").contains("license = \"MIT OR Apache-2.0\""),
        "the section states MIT OR Apache-2.0; Cargo.toml disagrees"
    );
    let deny = read("deny.toml");
    let licenses = deny
        .split("\n[licenses]\n")
        .nth(1)
        .expect("deny.toml has no [licenses] section, but the section says licenses are checked");
    assert!(
        licenses.contains("allow = ["),
        "deny.toml [licenses] has no allow list"
    );
    for l in ["\"MIT\"", "\"Apache-2.0\""] {
        assert!(licenses.contains(l), "deny.toml does not allow {l}");
    }
}

/// Source rule: the section says crates come from crates.io only and a git
/// fork cannot be pulled in. That is `[sources]` in deny.toml, plus the
/// absence of a `[patch]` override that would swap a crate for a fork.
#[test]
fn crates_io_only_rule_is_enforced() {
    let s = section();
    assert!(
        s.contains("crates.io"),
        "the section must say crates come from crates.io"
    );
    let deny = read("deny.toml");
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
            !read(manifest).contains("[patch"),
            "{manifest} has a [patch] override; the section says forks are not used"
        );
    }
}

/// The section tells contributors to turn off default features. That must
/// be what Cargo.toml actually does, or the advice is invented.
#[test]
fn default_features_advice_matches_cargo_toml() {
    assert!(section().contains("default-features = false"));
    assert!(
        read("Cargo.toml").contains("default-features = false"),
        "no dependency in Cargo.toml turns default features off"
    );
}

/// Both lockfiles are committed: tracked by git, not merely present on disk.
#[test]
fn lockfiles_are_tracked() {
    let out = Command::new("git")
        .args([
            "ls-files",
            "--error-unmatch",
            "Cargo.lock",
            "fuzz/Cargo.lock",
        ])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    assert!(
        out.status.success(),
        "a lockfile the Dependencies section calls committed is not tracked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Dependabot watches both cargo workspaces weekly, as the section says.
#[test]
fn dependabot_watches_both_cargo_workspaces_weekly() {
    let s = section();
    assert!(s.contains("Dependabot") && s.contains("weekly"));
    let cfg = read(".github/dependabot.yml");
    let blocks: Vec<&str> = cfg.split("- package-ecosystem:").skip(1).collect();
    for dir in ["\"/\"", "\"/fuzz\""] {
        let b = blocks
            .iter()
            .find(|b| {
                b.trim_start().starts_with("\"cargo\"") && b.contains(&format!("directory: {dir}"))
            })
            .unwrap_or_else(|| panic!("dependabot.yml has no cargo entry for directory {dir}"));
        assert!(
            b.contains("interval: \"weekly\""),
            "the cargo entry for {dir} is not weekly"
        );
    }
}

/// Every command the section tells a contributor to run is the command CI
/// runs, so running it locally reproduces the gate rather than an
/// approximation of it.
#[test]
fn local_commands_are_the_ci_commands() {
    let s = section();
    let ci = read(".github/workflows/ci.yml");
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
}

/// OSV-Scanner: the workflow really invokes the scanner over both lockfiles,
/// on pull requests and on the weekly schedule the section describes.
#[test]
fn osv_scanner_is_wired_as_described() {
    let s = section();
    assert!(s.contains("OSV-Scanner") && s.contains("Wednesday"));
    let wf = read(".github/workflows/osv-scanner.yml");
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
}
