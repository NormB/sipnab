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
    // systemctl (docs/mcp-setup.md)
    "now",
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
        ("docs/cli-reference.md", include_str!("../docs/cli-reference.md")),
        ("docs/filter-dsl.md", include_str!("../docs/filter-dsl.md")),
        ("docs/install.md", include_str!("../docs/install.md")),
        ("docs/mcp-overview.md", include_str!("../docs/mcp-overview.md")),
        ("docs/mcp-setup.md", include_str!("../docs/mcp-setup.md")),
        ("docs/mcp-tools.md", include_str!("../docs/mcp-tools.md")),
        ("docs/output-formats.md", include_str!("../docs/output-formats.md")),
        ("docs/examples.md", include_str!("../docs/examples.md")),
        (
            "docs/config-reference.md",
            include_str!("../docs/config-reference.md"),
        ),
        // Website documentation (Zola content) — same zero-drift contract.
        ("website/cli.md", include_str!("../website/content/docs/cli.md")),
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
        ("website/api.md", include_str!("../website/content/docs/api.md")),
        ("website/mcp.md", include_str!("../website/content/docs/mcp.md")),
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
        ("website/theme.md", include_str!("../website/content/docs/theme.md")),
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
