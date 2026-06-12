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
    "release",
    "target",
    "features",
    "no-default-features",
    "install",
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
    flags
}

/// Extract `--flag-name` tokens from markdown. Requires a letter after the
/// dashes so table rules (`|----|`) and `--` used as an em-dash don't match.
fn extract_long_flags(text: &str) -> BTreeSet<String> {
    let re = regex::Regex::new(r"--([A-Za-z][A-Za-z0-9-]*)").unwrap();
    re.captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

#[test]
fn readme_long_flags_exist_in_cli() {
    let readme = include_str!("../README.md");
    let mentioned = extract_long_flags(readme);

    // Sanity: extraction must find known-good flags, so this test can never
    // pass vacuously on a broken regex or an empty README.
    assert!(
        mentioned.contains("problems") && mentioned.contains("from"),
        "flag extraction is broken: expected to find --problems and --from in README"
    );

    let known = cli_long_flags();
    let phantom: Vec<&String> = mentioned
        .iter()
        .filter(|f| !known.contains(*f) && !FOREIGN_FLAGS.contains(&f.as_str()))
        .collect();

    assert!(
        phantom.is_empty(),
        "README.md advertises flags that do not exist in src/cli.rs: {phantom:?}\n\
         If a name is a --filter DSL alias, document it as `--filter <alias>`, \
         not as a standalone flag. If it belongs to a foreign tool (cargo etc.), \
         add it to FOREIGN_FLAGS in tests/docs_drift_test.rs."
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
