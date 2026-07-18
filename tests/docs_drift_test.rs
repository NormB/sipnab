//! Guards documentation against drift: every `--flag` README.md advertises
//! must actually exist in the CLI (clap) definition.
//!
//! Regression context: README once listed `--codec-asym`, `--ptime-asym`,
//! `--payload-asym`, `--duration-asym`, and `--late-media` as standalone
//! flags, but they are `--filter` DSL aliases only.
#![cfg(feature = "native")]

use clap::CommandFactory;
use std::collections::BTreeSet;

/// Long flags mentioned in README.md that belong to other tools
/// (cargo, cross, xcode-select), not to sipnab itself.
const FOREIGN_FLAGS: &[&str] = &[
    // cargo / cross / xcode-select
    "release",
    "target",
    "features",
    "no-default-features",
    "install",
    // docker (docs/install.md)
    "net",
    "rm",
    // apt (docs/install.md, website/install.md — noaudio .deb guidance)
    "no-install-recommends",
    // editcap (docs/cli-reference.md — `--strip-secrets` is the analog)
    "discard-all-secrets",
    // systemctl (docs/mcp.md)
    "now",
    // voipmonitor (docs/benchmarks.md comparison command lines)
    "config-file",
    // claude mcp add (website/mcp.md)
    "transport",
    "header",
];

/// All long flag names (including aliases) the real CLI accepts.
fn cli_long_flags() -> BTreeSet<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags = BTreeSet::new();
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long() {
            flags.insert(long.to_string());
        }
        if let Some(aliases) = arg.get_all_aliases() {
            for alias in aliases {
                flags.insert(alias.to_string());
            }
        }
    }
    // clap provides these automatically; get_arguments() doesn't list them.
    flags.insert("help".to_string());
    flags.insert("version".to_string());
    flags
}

/// Extract `--flag-name` tokens from markdown. Requires a letter after the
/// dashes so table rules (`|----|`) and `--` used as an em-dash don't match.
fn extract_long_flags(text: &str) -> BTreeSet<String> {
    let re = regex::Regex::new(r"--([A-Za-z][A-Za-z0-9-]*)").unwrap();
    re.captures_iter(text).map(|c| c[1].to_string()).collect()
}

#[test]
fn readme_long_flags_exist_in_cli() {
    // Every user-facing markdown file that shows commands. include_str!
    // means a deleted file fails the build, not silently skips.
    let docs: &[(&str, &str)] = &[
        ("README.md", include_str!("../README.md")),
        (
            "docs/cli-reference.md",
            include_str!("../docs/cli-reference.md"),
        ),
        ("docs/filter-dsl.md", include_str!("../docs/filter-dsl.md")),
        ("docs/install.md", include_str!("../docs/install.md")),
        ("docs/mcp.md", include_str!("../docs/mcp.md")),
        (
            "docs/troubleshooting.md",
            include_str!("../docs/troubleshooting.md"),
        ),
        ("docs/rest-api.md", include_str!("../docs/rest-api.md")),
        (
            "docs/output-formats.md",
            include_str!("../docs/output-formats.md"),
        ),
        ("docs/examples.md", include_str!("../docs/examples.md")),
        (
            "docs/config-reference.md",
            include_str!("../docs/config-reference.md"),
        ),
        (
            "docs/keybindings.md",
            include_str!("../docs/keybindings.md"),
        ),
        ("docs/auth.md", include_str!("../docs/auth.md")),
        (
            "docs/theme-guide.md",
            include_str!("../docs/theme-guide.md"),
        ),
        ("docs/library.md", include_str!("../docs/library.md")),
        ("docs/benchmarks.md", include_str!("../docs/benchmarks.md")),
        (
            "docs/fault-model.md",
            include_str!("../docs/fault-model.md"),
        ),
        // Website documentation (Zola content) — same zero-drift contract.
        (
            "website/cli.md",
            include_str!("../website/content/docs/cli.md"),
        ),
        (
            "website/cookbook.md",
            include_str!("../website/content/docs/cookbook.md"),
        ),
        (
            "website/filter-dsl.md",
            include_str!("../website/content/docs/filter-dsl.md"),
        ),
        (
            "website/install.md",
            include_str!("../website/content/docs/install.md"),
        ),
        (
            "website/api.md",
            include_str!("../website/content/docs/api.md"),
        ),
        (
            "website/api-clients.md",
            include_str!("../website/content/docs/api-clients.md"),
        ),
        (
            "website/integrations.md",
            include_str!("../website/content/docs/integrations.md"),
        ),
        (
            "website/build.md",
            include_str!("../website/content/docs/build.md"),
        ),
        (
            "website/mcp.md",
            include_str!("../website/content/docs/mcp.md"),
        ),
        (
            "website/troubleshooting.md",
            include_str!("../website/content/docs/troubleshooting.md"),
        ),
        (
            "website/config.md",
            include_str!("../website/content/docs/config.md"),
        ),
        (
            "website/keybindings.md",
            include_str!("../website/content/docs/keybindings.md"),
        ),
        (
            "website/theme.md",
            include_str!("../website/content/docs/theme.md"),
        ),
        (
            "website/landing.md",
            include_str!("../website/content/_index.md"),
        ),
        (
            "website/analyze.md",
            include_str!("../website/content/analyze/_index.md"),
        ),
    ];

    let known = cli_long_flags();
    let mut all_mentioned = BTreeSet::new();
    let mut failures = Vec::new();
    for (name, text) in docs {
        let mentioned = extract_long_flags(text);
        let phantom: Vec<&String> = mentioned
            .iter()
            .filter(|f| !known.contains(*f) && !FOREIGN_FLAGS.contains(&f.as_str()))
            .collect();
        if !phantom.is_empty() {
            failures.push(format!("{name}: {phantom:?}"));
        }
        all_mentioned.extend(mentioned);
    }

    // Sanity: extraction must find known-good flags, so this test can never
    // pass vacuously on a broken regex or empty docs.
    assert!(
        all_mentioned.contains("problems") && all_mentioned.contains("from"),
        "flag extraction is broken: expected to find --problems and --from"
    );

    assert!(
        failures.is_empty(),
        "docs advertise flags that do not exist in src/cli.rs:\n  {}\n\
         If a name is a --filter DSL alias, document it as `--filter <alias>`, \
         not as a standalone flag. If it belongs to a foreign tool (cargo etc.), \
         add it to FOREIGN_FLAGS in tests/docs_drift_test.rs.",
        failures.join("\n  ")
    );
}

#[test]
fn readme_documents_audio_runtime_dependency_and_headless_recipe() {
    // The `audio` default feature needs libasound at runtime; README must
    // keep saying so AND keep showing a no-audio recipe for headless hosts
    // (same warning build.rs emits — keep the two in sync).
    let readme = include_str!("../README.md");
    assert!(
        readme.contains("libasound"),
        "README must document the libasound runtime dependency of the audio feature"
    );
    assert!(
        readme.contains("--no-default-features"),
        "README must show a --no-default-features recipe to drop the audio feature"
    );
}

#[test]
fn extraction_ignores_table_rules_and_em_dashes() {
    let md = "| a |\n|----|\n**Bold** -- prose with -- dashes\n`--real-flag` and ---triple";
    let got = extract_long_flags(md);
    assert_eq!(
        got,
        BTreeSet::from(["real-flag".to_string(), "triple".to_string()]),
        "extractor must skip table rules and spaced em-dashes (`---triple` \
         intentionally matches: a doc typo like `---flag` should be flagged, \
         and `triple` won't be a known flag)"
    );
}

/// Split a markdown document into its fenced code blocks (``` ... ```).
fn fenced_blocks(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            match current.take() {
                Some(done) => blocks.push(done),
                None => current = Some(String::new()),
            }
            continue;
        }
        if let Some(buf) = current.as_mut() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    blocks
}

/// Regression guard: every documented `--mcp` invocation once omitted the
/// mandatory `-N`/`--no-tui`, so copy-pasting ANY example hit a hard CLI
/// error ("--mcp implies non-interactive mode"). Any fenced example that
/// starts sipnab with `--mcp` must also pass `-N` or `--no-tui`.
#[test]
fn mcp_examples_always_pass_no_tui() {
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir("docs").expect("docs dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let md = std::fs::read_to_string(&path).expect("read doc");
        for block in fenced_blocks(&md) {
            // Join backslash continuations so a multi-line command is
            // checked as one logical invocation.
            let mut logical: Vec<String> = Vec::new();
            let mut cont = String::new();
            for line in block.lines() {
                if let Some(head) = line.trim_end().strip_suffix('\\') {
                    cont.push_str(head);
                    cont.push(' ');
                    continue;
                }
                cont.push_str(line);
                logical.push(std::mem::take(&mut cont));
            }
            for line in logical {
                // A bare `--mcp` (not an `--mcp-*` option like
                // --mcp-transport).
                let has_bare_mcp = line
                    .match_indices("--mcp")
                    .any(|(i, _)| !matches!(line.as_bytes().get(i + 5), Some(b'-')));
                // No "sipnab" requirement: client-config lines like
                // `"args": ["--mcp", ...]` name the binary elsewhere.
                if has_bare_mcp && !(line.contains("-N") || line.contains("--no-tui")) {
                    offenders.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "--mcp examples missing -N/--no-tui (copy-paste would fail):\n{}",
        offenders.join("\n---\n")
    );
}

/// Regression guard: the Code of Conduct once shipped with the enforcement
/// contact deleted (the INSERT-CONTACT-METHOD placeholder removed rather
/// than filled), leaving no way to report an incident.
#[test]
fn code_of_conduct_has_enforcement_contact() {
    let coc = std::fs::read_to_string("CODE_OF_CONDUCT.md").expect("CODE_OF_CONDUCT.md");
    assert!(
        !coc.to_ascii_uppercase().contains("[INSERT"),
        "unfilled Contributor Covenant placeholder"
    );
    // Anchor on the exact heading — "## Enforcement Responsibilities"
    // comes first in the covenant and would otherwise win the split.
    let enforcement = coc
        .split("## Enforcement\n")
        .nth(1)
        .expect("Enforcement section present");
    assert!(
        enforcement.contains('@') && enforcement.contains("mailto:"),
        "Enforcement section must name a working contact (mailto link)"
    );
    // And the repo actually points people at it.
    let readme = std::fs::read_to_string("README.md").expect("README.md");
    assert!(
        readme.contains("CODE_OF_CONDUCT.md"),
        "README must link the Code of Conduct"
    );
}

/// The man page must track the crate: its .TH version and LICENSE section
/// once rotted to "0.4.18" / "GPL-3.0-only" while Cargo.toml said 0.5.2 /
/// "MIT OR Apache-2.0" — a licensing contradiction, not just staleness.
#[test]
fn man_page_version_and_license_match_cargo() {
    let man = include_str!("../man/sipnab.1");
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        man.contains(&format!("\"sipnab {version}\"")),
        "man/sipnab.1 .TH version must be the crate version {version}"
    );
    assert!(
        !man.contains("GPL"),
        "man/sipnab.1 license drifted: Cargo.toml says MIT OR Apache-2.0"
    );
    assert!(
        man.contains("MIT OR Apache-2.0"),
        "man/sipnab.1 must state the MIT OR Apache-2.0 license"
    );
}

/// "Current version" strings sprinkled through the install/benchmark docs
/// must equal the crate version — they sit outside the pre-commit gate that
/// keeps website/config.toml in sync, so they rot on every release without
/// this guard. Historical references (e.g. the benchmark provenance
/// "0.4.16") are deliberately NOT matched.
#[test]
fn docs_current_version_markers_match_cargo() {
    let version = env!("CARGO_PKG_VERSION");
    // (path, contents, marker regex whose capture 1 must be the crate version)
    let sources: &[(&str, &str, &str)] = &[
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"SIPNAB_VERSION=(\d+\.\d+\.\d+)",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"e\.g\. (\d+\.\d+\.\d+)",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab-(\d+\.\d+\.\d+)-1\.x86_64\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"e\.g\. (\d+\.\d+\.\d+)",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/benchmarks.md",
            include_str!("../website/content/docs/benchmarks.md"),
            r"current release (\d+\.\d+\.\d+)",
        ),
        (
            "website/content/docs/api.md",
            include_str!("../website/content/docs/api.md"),
            r"as of (\d+\.\d+\.\d+)",
        ),
    ];
    for (path, text, pattern) in sources {
        let re = regex::Regex::new(pattern).unwrap();
        let mut matched = false;
        for cap in re.captures_iter(text) {
            matched = true;
            assert_eq!(
                &cap[1], version,
                "{path}: current-version marker '{pattern}' names {} but the crate \
                 is {version} — update the doc (or this marker list)",
                &cap[1]
            );
        }
        assert!(
            matched,
            "{path}: expected at least one '{pattern}' marker; the doc changed — \
             update the marker list"
        );
    }
}
