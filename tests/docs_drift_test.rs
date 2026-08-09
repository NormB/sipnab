// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guards documentation against drift: every `--flag` README.md advertises
//! must actually exist in the CLI (clap) definition.
//!
//! Regression context: README once listed `--codec-asym`, `--ptime-asym`,
//! `--payload-asym`, `--duration-asym`, and `--late-media` as standalone
//! flags, but they are `--filter` DSL aliases only.
//!
//! Beyond flag drift, this crate also pins other doc-vs-reality contracts:
//! `--mcp` examples must pass `-N`/`--no-tui`, the Code of Conduct must keep
//! a working enforcement contact, the man page must match the crate version
//! and license, "current version" markers in install/benchmark docs must
//! match Cargo.toml, and the benchmark tables must stay identical between
//! the wiki source and the website copy. Gated on the `native` feature
//! because it introspects the real clap `Cli`.
#![cfg(feature = "native")]

use clap::CommandFactory;
use std::collections::BTreeSet;

#[path = "support/markdown.rs"]
mod markdown;

/// Long flags mentioned in the docs that belong to OTHER tools (cargo, docker,
/// apt, editcap, systemctl, voipmonitor, `claude mcp add`), not to sipnab —
/// each scoped to the exact doc label(s) where it legitimately appears.
///
/// Scoping (rather than a flat global allowlist) keeps a foreign name from
/// masking a real sipnab-flag typo in an unrelated doc: e.g. `--target` is a
/// cargo/xcode flag excused only in the build/install docs, so a stray
/// `--target` written as if it were a sipnab flag in `docs/cli-reference.md`
/// would still fail this guard instead of being silently whitelisted. The
/// label is the first element of each `docs` tuple in `readme_long_flags_exist_in_cli`.
const FOREIGN_FLAGS: &[(&str, &[&str])] = &[
    // `rustc --print deployment-target`, in the macOS floor recipe. The floors
    // are the compiler's defaults, so the compiler is what the doc tells the
    // reader to ask — a copy of the number would be the thing this avoids.
    (
        "print",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // cargo / cross / xcode-select build & install recipes
    (
        "release",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "docs/mcp.md",
            "docs/rest-api.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/api.md",
            "website/content/docs/build.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
        ],
    ),
    (
        "target",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    // `cargo install --path <dir> --bin sipnab`, in the source-install recipe.
    // --bin is load-bearing there, not decoration: without it cargo installs
    // every [[bin]] whose required-features are met, and gen_fixture's are.
    (
        "path",
        &[
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    (
        "bin",
        &[
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    // `rustc --cfg sipnab_tsan`, in the ThreadSanitizer section: the flag that
    // drops mimalloc for the sanitizer build. A rustc flag, not a sipnab one.
    (
        "cfg",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    // `sha256sum --ignore-missing` and `gh attestation verify --repo`, in the
    // download-verification recipes.
    (
        "ignore-missing",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    (
        "repo",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // Alpine's package manager, in the musl/Alpine build recipes.
    ("no-cache", &["website/content/docs/build.md"]),
    // contrib/mcp/trace-call.py's own flags, in the "Drive it from a script"
    // section. That script is an MCP *client*: it never launches sipnab, so
    // these are argparse options belonging to the example, not sipnab's CLI.
    // Scoped to the two mcp-walkthrough surfaces so the same names anywhere
    // else still fail the gate.
    (
        "node",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "call-id",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "token-file",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    // bench/carrier.py and bench/scaling.sh flags, in the reproduce recipes.
    // These belong to the benchmark harness, not to sipnab's CLI.
    (
        "calls",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "out",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "call-ids",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "stream-pairs",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "runs",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "features",
        &[
            "README.md",
            "docs/install.md",
            "docs/mcp.md",
            "docs/rest-api.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/install.md",
            "website/content/docs/api.md",
            "website/content/docs/build.md",
            "website/content/docs/_index.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "no-default-features",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "docs/mcp.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/build.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
            "CONTRIBUTING.md",
        ],
    ),
    // useradd / systemctl / certbot / claude-cli, in the deployment scenarios
    // of the MCP walkthrough. That page was outside the old hand list entirely,
    // which is how it could have advertised a renamed --mcp-* flag on both the
    // wiki and the site with this suite green.
    (
        "system",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "home",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "shell",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "no-pager",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "nginx",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "allowedTools",
        &[
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    // The benchmark harness flags were excused for docs/benchmarks.md but not
    // for its hand-maintained site twin, which is deliberately not generated.
    // Developer-tree tool flags: cargo, npm, git, insta and the `--your-flag`
    // placeholder in the "add a CLI flag" walkthrough. docs/internals/ is in the
    // corpus because it is published (wiki + site nav), so a phantom sipnab flag
    // there is a real defect; these belong to other tools and are excused per page.
    (
        "accept",
        &[
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "all-features",
        &[
            "docs/internals/README.md",
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/_index.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "all-targets",
        &[
            "docs/internals/README.md",
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/_index.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "bin",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "calls",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "check",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "features",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
        ],
    ),
    (
        "flag",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "ignored",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/tui-testing.md",
        ],
    ),
    (
        "install-",
        &[
            "docs/internals/README.md",
            "website/content/docs/internals/_index.md",
        ],
    ),
    (
        "no-default-features",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "no-deps",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "no-typescript",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "out",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "out-dir",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "package",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "path",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "profile",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "repo",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "runs",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "target",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "test",
        &[
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
        ],
    ),
    (
        "tests",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            // CONTRIBUTING's pre-push table quotes the feature-matrix gate,
            // whose whole point is the `--tests` cargo flag: without it the
            // matrix compiles no test file and passes over nothing.
            "CONTRIBUTING.md",
        ],
    ),
    (
        "workspace",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "your-flag",
        &[
            "docs/internals/walkthroughs.md",
            "website/content/docs/internals/walkthroughs.md",
        ],
    ),
    // `cargo fmt --all -- --check`, the hook gate. Named in CONTRIBUTING's hook
    // tables and, since the check moved into pre-commit as gate 0, in the
    // build-and-CI internals page that enumerates those gates.
    (
        "all",
        &[
            "CONTRIBUTING.md",
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    ("install", &["README.md", "CONTRIBUTING.md"]),
    // docker run flags (install docs)
    (
        "net",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    (
        "rm",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // apt (noaudio .deb guidance)
    (
        "no-install-recommends",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // editcap (`--strip-secrets` is sipnab's analog)
    (
        "discard-all-secrets",
        &["docs/cli-reference.md", "website/content/docs/cli.md"],
    ),
    // systemctl (mcp service management)
    (
        "now",
        &[
            "docs/mcp.md",
            "website/content/docs/mcp.md",
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    // voipmonitor (benchmark comparison command lines)
    (
        "config-file",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    // claude mcp add (http-transport client wiring)
    (
        "transport",
        &[
            "docs/mcp.md",
            "website/content/docs/mcp.md",
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
    (
        "header",
        &[
            "docs/mcp.md",
            "website/content/docs/mcp.md",
            "docs/mcp-walkthrough.md",
            "website/content/docs/mcp-walkthrough.md",
        ],
    ),
];

/// True when `flag` is a known foreign-tool flag excused in `doc` specifically.
/// A foreign flag mentioned in a doc outside its scope is NOT excused, so it
/// surfaces as drift.
fn is_foreign_flag(flag: &str, doc: &str) -> bool {
    FOREIGN_FLAGS
        .iter()
        .any(|(name, docs)| *name == flag && docs.contains(&doc))
}

/// All long flag names (including aliases) the real CLI accepts.
///
/// # Returns
/// The set of long option names, plus the implicit `help`/`version`.
fn cli_long_flags() -> BTreeSet<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags = BTreeSet::new();

    // Flags that exist only under a non-default Cargo feature.
    //
    // This enumerates the CLI clap actually built, so a `#[cfg(feature = ...)]`
    // flag is absent whenever the suite runs without that feature — and the
    // docs, which describe the whole program, still name it. The reduced-feature
    // CI matrix hits exactly that: `--plugin` is real under `plugins` and
    // invisible under `native,hep,api,mcp,mcp-http`, so the gate reported the
    // documentation as advertising a flag that does not exist.
    //
    // Listed rather than inferred, so adding a feature-gated flag is a
    // deliberate entry here and not something a reader has to discover from a
    // red matrix job. Each name must still be documented like any other flag.
    const FEATURE_GATED: &[&str] = &["plugin"];
    for f in FEATURE_GATED {
        flags.insert((*f).to_string());
    }

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
///
/// # Returns
/// The distinct flag names found, without the leading dashes.
fn extract_long_flags(text: &str) -> BTreeSet<String> {
    // Strip markdown link targets first. GitHub-style heading anchors embed a
    // double hyphen wherever the heading had an em dash, so
    // `](#scenario-5--a-fleet-of-capture-hosts)` otherwise reads as a flag
    // named `--a-fleet-of-capture-hosts`. One page carries 19 of them.
    static LINK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let link = LINK.get_or_init(|| regex::Regex::new(r"\]\([^)]*\)").unwrap());
    let text = link.replace_all(text, "]");

    let re = regex::Regex::new(r"--([A-Za-z][A-Za-z0-9-]*)").unwrap();
    re.captures_iter(&text).map(|c| c[1].to_string()).collect()
}

/// Every published markdown page, as `(repo-relative path, contents)`.
///
/// The published surface is everything a reader can reach: the repository root
/// pages, all of `docs/` including `docs/internals/`, and the Zola content
/// tree. Only the planning trees are excluded, for the same reason
/// `link_integrity_test` excludes them — they are a historical record, not
/// documentation anyone is pointed at, and editing them to satisfy a gate
/// corrupts them.
///
/// `docs/internals/` is in scope because it is PUBLISHED: `build-wiki.py` maps
/// all ten pages to `Internals-*` wiki pages and the site nav links the
/// mirrors. An earlier version of this excluded it, with a comment claiming it
/// was covered because "its own drift gates live in dev_docs_drift_test" —
/// true for links, symbols and mermaid, and false for flags, which that file
/// never checks. A phantom flag added there passed 82 tests while live on two
/// published pages.
fn published_markdown() -> Vec<(String, String)> {
    // Root pages a reader reaches. CONTRIBUTING.md is in: a phantom sipnab
    // flag there misleads a contributor, which is a real reader.
    //
    // Two root pages stay out, on principle rather than convenience:
    //   CHANGELOG.md — a historical record. An entry naming a flag that has
    //     since been renamed or removed is CORRECT, and gating it against the
    //     current CLI would force the history to be rewritten to stay green.
    //   THIRD-PARTY-NOTICES.md — generated from the dependency tree; its
    //     content is not authored here.
    const ROOT_PAGES: &[&str] = &["README.md", "SECURITY.md", "CONTRIBUTING.md"];
    const SKIP: &[&str] = &["docs/design/", "docs/research/", "docs/superpowers/"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    let mut pages: Vec<(String, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|rel| {
            if SKIP.iter().any(|d| rel.starts_with(d)) {
                return false;
            }
            let in_docs = rel.starts_with("docs/");
            in_docs || rel.starts_with("website/content/") || ROOT_PAGES.contains(rel)
        })
        .filter_map(|rel| {
            std::fs::read_to_string(root.join(rel))
                .ok()
                .map(|t| (rel.to_string(), t))
        })
        .collect();
    assert!(
        pages.len() >= 55,
        "only {} published markdown pages found — the derivation is reading \
         almost nothing and every gate built on it passes vacuously",
        pages.len()
    );
    pages.sort();
    pages
}

/// Every `--flag` mentioned across the user-facing docs exists in the clap
/// CLI (or is a whitelisted foreign-tool flag); extraction is self-checked.
#[test]
fn readme_long_flags_exist_in_cli() {
    // Derived from the tree, not hand-listed. The old list held 34
    // include_str! entries and missed three published pages:
    // docs/mcp-walkthrough.md carried 21 long-flag tokens and is rendered on
    // both the wiki and the site, so a renamed --mcp-* flag could ship live on
    // two surfaces with this suite green. Demonstrated: a phantom flag added
    // there passed 85 tests, while the same string in a listed page failed.
    //
    // include_str! bought a build error when a listed file was deleted. A
    // derived list is strictly better for that purpose: a renamed file is
    // still scanned under its new name, where before it silently left the
    // corpus.
    let corpus = published_markdown();
    let docs: Vec<(&str, &str)> = corpus
        .iter()
        .map(|(label, text)| (label.as_str(), text.as_str()))
        .collect();
    let docs = &docs[..];

    let known = cli_long_flags();
    let mut all_mentioned = BTreeSet::new();
    let mut failures = Vec::new();
    for (name, text) in docs {
        let mentioned = extract_long_flags(text);
        let phantom: Vec<&String> = mentioned
            .iter()
            .filter(|f| !known.contains(*f) && !is_foreign_flag(f, name))
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
         add it to FOREIGN_FLAGS in tests/docs_drift_test.rs, scoped to this doc's label.",
        failures.join("\n  ")
    );
}

/// README keeps the libasound runtime note and a --no-default-features headless recipe.
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

/// The flag extractor skips table rules and spaced dashes but still flags `---triple` typos.
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
///
/// # Returns
/// The body text of each fenced block, in document order.
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
///
/// Covers both the wiki-source docs (`docs/`) and the published website
/// (`website/content/docs/`) — the website's mcp.md carries its own copy of
/// these examples, so a broken example there must fail this test too.
#[test]
fn mcp_examples_always_pass_no_tui() {
    let mut offenders = Vec::new();
    let doc_dirs = ["docs", "website/content/docs"];
    let entries = doc_dirs.iter().flat_map(|dir| {
        std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read doc dir {dir}: {e}"))
            .map(|entry| entry.expect("dir entry").path())
    });
    for path in entries {
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

/// The security policy must keep a reachable disclosure address.
///
/// The Code of Conduct has been guarded this way since its enforcement contact
/// was once deleted outright. SECURITY.md carries the more consequential
/// address of the two — it is where an unreported vulnerability goes — and had
/// no such guard, so the same edit that broke the CoC would have gone unnoticed
/// here. It also promises response times, which are worthless if the address
/// they attach to has quietly vanished.
#[test]
fn security_policy_has_a_reporting_contact() {
    let sec = std::fs::read_to_string("SECURITY.md").expect("SECURITY.md");

    let email = regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
    let found = email.find(&sec).map(|m| m.as_str().to_string());
    assert!(
        found.is_some(),
        "SECURITY.md names no email address — a vulnerability reporter has \
         nowhere to send a report, and the response-time table below promises \
         a reply to an address that does not exist"
    );

    assert!(
        !sec.to_ascii_uppercase().contains("[INSERT") && !sec.contains("TODO"),
        "SECURITY.md still carries a placeholder instead of a real contact"
    );

    // The instruction not to file publicly is the whole point of the private
    // channel; losing it sends reports to the issue tracker.
    assert!(
        sec.to_ascii_lowercase()
            .contains("do not open a public issue"),
        "SECURITY.md no longer tells reporters to avoid public issues"
    );

    // And the project must actually point people at the policy.
    let readme = std::fs::read_to_string("README.md").expect("README.md");
    assert!(
        readme.contains("SECURITY.md"),
        "README does not link SECURITY.md, so the policy is unreachable from \
         the front door"
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

    // Markers that tell a reader WHICH VERSION TO DOWNLOAD track the last
    // PUBLISHED release, not the crate version in the tree. They are two
    // different facts, and this list used to conflate them exactly the way
    // `/download` did before `published_version` existed: a release commit
    // bumps `Cargo.toml`, this gate then demanded the docs say the new number,
    // and for the whole commit -> CI -> tag -> release-build window the
    // documented `SIPNAB_VERSION=x.y.z` named a release that did not exist. A
    // reader copying that line got a 404 from install.sh.
    //
    // `install.sh` itself is unaffected — with `SIPNAB_VERSION` unset it asks
    // the API for the latest release — so this only ever bit the person who
    // followed the documented pinned example.
    let published = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(include_str!("../website/config.toml"))
        .expect("website/config.toml has no published_version")[1]
        .to_string();
    let download_markers: &[(&str, &str, &str)] = &[
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
        // Every rpm variant, not just the x86_64 standard one. The pattern was
        // `-1\.x86_64\.rpm`, which pinned line one of three `rpm -i` recipes
        // sitting in the same section -- the `-noaudio` and `aarch64` lines went
        // ungated and were still naming 0.5.63 while the gated line moved. Same
        // section, same copy-paste, same 404; the gate simply could not see two
        // thirds of it. The arch and variant are alternations so a new package
        // flavour is covered the day it is documented.
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab-(\d+\.\d+\.\d+)-1\.(?:x86_64|aarch64)(?:-noaudio)?\.rpm",
        ),
        // The alternation above gates the version of whatever `rpm -i` recipes
        // the page HAPPENS to carry. It says nothing about one that is missing,
        // and one was: a release publishes four rpms, while install.md
        // documented three commands -- x86_64, x86_64-noaudio, aarch64. The
        // published `sipnab-<version>-1.aarch64-noaudio.rpm` had no line naming
        // it anywhere on the page, so an arm64 headless reader had to guess the
        // filename off the packaging table. Same section and same copy-paste as
        // the drift the comment above records, one step further along: there the
        // gate could not see two thirds of the recipes, here it could not see
        // that a quarter of the packages had no recipe at all.
        //
        // Each entry below pins one exact variant, so the loop's "expected at
        // least one" assertion fires the moment a recipe disappears -- and each
        // still tracks published_version like every other download marker. Add
        // one whenever the release workflow grows a package flavour, and add the
        // `rpm -i` line it gates.
        //
        // Only docs/install.md is listed: website/content/docs/install.md is
        // generated from it, and site_pages_mirror_is_current compares the two
        // byte-for-byte, so the mirror cannot carry a different set of recipes.
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.x86_64\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.x86_64-noaudio\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.aarch64\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.aarch64-noaudio\.rpm",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"e\.g\. (\d+\.\d+\.\d+)",
        ),
    ];
    for (path, text, pattern) in download_markers {
        let re = regex::Regex::new(pattern).unwrap();
        let mut matched = false;
        for cap in re.captures_iter(text) {
            matched = true;
            assert_eq!(
                &cap[1], published,
                "{path}: download marker '{pattern}' names {} but the last \
                 PUBLISHED release is {published} — a reader copying this would \
                 fetch a version that does not exist yet. Download instructions \
                 track published_version, not Cargo.toml.",
                &cap[1]
            );
        }
        assert!(
            matched,
            "{path}: expected at least one '{pattern}' marker; the doc changed \
             — update the marker list"
        );
    }

    // (path, contents, marker regex whose capture 1 must be the CRATE version)
    let sources: &[(&str, &str, &str)] = &[
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        // The benchmarks pages deliberately have NO current-version marker.
        //
        // They used to. Both carried "the current release X is N later", and
        // this list required X to equal the crate version — so every release
        // mechanically advanced it, and the sentence went on looking current
        // while the measurement behind it aged twenty-nine releases. The gate
        // was not merely failing to catch the staleness; it was manufacturing
        // the appearance of freshness.
        //
        // The pages now state the release they were MEASURED on, which is a
        // historical fact and must not track Cargo.toml. It is gated instead by
        // benchmark_pages_agree_on_what_was_measured, below.
        // The `sipnab X.Y.Z (…) features:` sample output was only gated in the
        // install pages; the MCP walkthroughs print it too.
        //
        // Scope note: this pattern only matches the form with a commit hash in
        // parentheses. A bare `sipnab 0.5.20 features:` line once slipped
        // through and sat stale for 23 releases. It is gone now, and the
        // remaining version mention in those pages is a deliberately historical
        // "verified at 0.5.20" — which does not rot — so there is nothing left
        // for a no-paren pattern to guard. Do not reintroduce a bare
        // `sipnab <version> features:` sample without gating it.
        (
            "docs/mcp-walkthrough.md",
            include_str!("../docs/mcp-walkthrough.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/mcp-walkthrough.md",
            include_str!("../website/content/docs/mcp-walkthrough.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        // `website/content/docs/api.md` used to be gated here on an
        // `as of <version>` marker, and the entry is gone for the same reason
        // the benchmark pages lost theirs.
        //
        // The sentence it tracked said "as of <version> nothing in the capture
        // path records into sipnab_security_alerts_total", and this gate
        // advanced that version on every release. The recording call landed in
        // `AlertEngine::fire`, `firing_an_alert_moves_the_metric` stopped being
        // ignored, and the sentence became false — while this gate went on
        // dutifully renumbering it, which made a stale claim look freshly
        // checked. The gate was not failing to catch the rot. It was dressing
        // it up.
        //
        // The paragraph now describes what the metric does and dates the old
        // behaviour as history ("up to 0.5.74"), which must NOT track
        // Cargo.toml. Nothing on that page names a current version any more, so
        // nothing there belongs in this list.
        // The `server_capabilities` sample in the diagnostic cookbook. It is
        // real captured output, so it names the build that produced it — which
        // is exactly why it needs gating rather than trusting: the recipes are
        // there to be recognised mid-incident, and a reader comparing their own
        // output against a version three releases stale has to work out whether
        // the difference matters.
        //
        // Distinct from the `sipnab X.Y.Z (` pattern above because this is a
        // JSON field rather than a `--version` line. It went in ungated and is
        // listed here rather than left to rot the way the bare
        // `sipnab 0.5.20 features:` sample did for 23 releases.
        (
            "docs/mcp-walkthrough.md",
            include_str!("../docs/mcp-walkthrough.md"),
            r#""version": "(\d+\.\d+\.\d+)""#,
        ),
        (
            "website/content/docs/mcp-walkthrough.md",
            include_str!("../website/content/docs/mcp-walkthrough.md"),
            r#""version": "(\d+\.\d+\.\d+)""#,
        ),
        // The same server_capabilities sample appears in the MCP reference.
        // Gating only the walkthrough left this one drifting: it still named
        // 0.5.69 after the crate moved to 0.5.70, in the same release that
        // added the gate. Two copies of one sample, one of them watched.
        (
            "docs/mcp.md",
            include_str!("../docs/mcp.md"),
            r#""version": "(\d+\.\d+\.\d+)""#,
        ),
        (
            "website/content/docs/mcp.md",
            include_str!("../website/content/docs/mcp.md"),
            r#""version": "(\d+\.\d+\.\d+)""#,
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

// ---------------------------------------------------------------------------
// The benchmarks page exists twice — docs/benchmarks.md (source of the GitHub
// Wiki) and website/content/docs/benchmarks.md (the site) — with deliberately
// different framing but the SAME measured data. A re-benchmark once landed
// only on the website (0.5.18 numbers) while the wiki kept publishing the
// 0.4.16 tables plus a perf claim the same PR had retracted. The prose may
// differ; the tables may not.
// ---------------------------------------------------------------------------

/// The markdown table rows of docs/benchmarks.md and the website benchmarks page are identical.
#[test]
fn benchmark_tables_match_between_docs_and_website() {
    /// The markdown table rows (lines starting with `|`) of a document,
    /// trailing whitespace trimmed.
    fn rows(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|l| l.starts_with('|'))
            .map(str::trim_end)
            .collect()
    }
    let docs = rows(include_str!("../docs/benchmarks.md"));
    let site = rows(include_str!("../website/content/docs/benchmarks.md"));
    assert_eq!(
        docs, site,
        "benchmark tables differ between docs/benchmarks.md (wiki source) and \
         website/content/docs/benchmarks.md — re-benchmarks must update BOTH \
         files in the same commit, or the wiki publishes stale numbers"
    );
}

/// `response_class()` agrees with the classification in the reference page.
///
/// `docs/sip-response-codes.md` groups all 75 registry codes under seven class
/// headings, and `sipnab::sip::response_codes::response_class` decides the same
/// question in code. Two statements of one fact is the bug class this repository
/// keeps finding: the dialog state machine restated it a third way, as inline
/// ranges across four handlers, and two defects lived in the gaps.
///
/// Reads the page rather than a copy of it, so adding a code to the doc without
/// teaching the classifier fails here.
#[test]
fn response_class_matches_the_documented_table() {
    use sipnab::sip::response_codes::{ResponseClass, response_class};

    let doc = include_str!("../docs/sip-response-codes.md");
    // Section heading -> class. The page titles them for a reader; map back.
    let heading_class = |h: &str| -> Option<ResponseClass> {
        match h {
            "1xx provisional" => Some(ResponseClass::Provisional),
            "2xx success" => Some(ResponseClass::Success),
            "3xx redirect" => Some(ResponseClass::Redirect),
            "Challenge" => Some(ResponseClass::Challenge),
            "Cancelled" => Some(ResponseClass::Cancelled),
            "Declined" => Some(ResponseClass::Declined),
            "Failure" => Some(ResponseClass::Failure),
            _ => None,
        }
    };
    let row = regex::Regex::new(r"(?m)^\| `(\d{3})` \|").unwrap();
    let head = regex::Regex::new(r"(?m)^## (.+)$").unwrap();

    let mut current: Option<ResponseClass> = None;
    let mut checked = 0usize;
    for line in doc.lines() {
        if let Some(c) = head.captures(line) {
            current = heading_class(c[1].trim());
            continue;
        }
        let Some(c) = row.captures(line) else {
            continue;
        };
        let Some(expected) = current else { continue };
        let code: u16 = c[1].parse().expect("three digits");
        assert_eq!(
            response_class(code),
            expected,
            "docs/sip-response-codes.md files {code} under {expected:?}, but \
             response_class() says {:?}",
            response_class(code)
        );
        checked += 1;
    }
    assert_eq!(
        checked, 75,
        "checked {checked} codes against the page, expected all 75 — the table \
         shape changed and this gate is reading less than it claims"
    );
}

/// Every `DialogState` value appears in the docs that enumerate them.
///
/// Three pages list the states as prose — the filter DSL's valid values, the
/// REST API's `state` query parameter, and the `sipnab_dialogs_total{state}`
/// metric — and a fourth enumeration lives in `config_wiring_test`. None of the
/// four is compiler-enforced, unlike the five `match` arms over the enum, which
/// cannot compile if a variant is missed.
///
/// That asymmetry is the whole reason this exists: adding `Redirected` broke
/// five matches loudly and would have left four lists quietly wrong. A filter
/// value nobody documents is a filter nobody uses.
#[test]
fn documented_dialog_states_cover_the_enum() {
    // The enumeration, mirrored from `DialogState`. Adding a variant without
    // adding it here passes; adding it here without documenting it fails, which
    // is the direction that matters — the docs are what a reader has.
    const STATES: [&str; 13] = [
        "Trying",
        "Ringing",
        "InCall",
        "Completed",
        "Cancelled",
        "Failed",
        "Redirected",
        "Registered",
        "Expired",
        "Pending",
        "Active",
        "Terminated",
        "Transferring",
    ];
    let pages: [(&str, &str); 2] = [
        ("docs/filter-dsl.md", include_str!("../docs/filter-dsl.md")),
        ("docs/rest-api.md", include_str!("../docs/rest-api.md")),
    ];
    for (path, text) in pages {
        for state in STATES {
            assert!(
                text.contains(&format!("`{state}`")),
                "{path} never mentions the `{state}` dialog state — a reader \
                 cannot filter on a value the page does not list"
            );
        }
    }
}

/// Docs that state the fuzz-target count as current must match the tree.
///
/// `docs/fault-model.md` also names every target, so a new one added without
/// touching that list leaves the page describing a fuzz surface smaller than
/// the real one — a security-facing page understating security coverage.
/// Nothing checked either the number or the names.
#[test]
fn fuzz_target_count_and_names_match_the_tree() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut actual: Vec<String> = std::fs::read_dir(repo.join("fuzz/fuzz_targets"))
        .expect("fuzz/fuzz_targets must exist")
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()? != "rs" {
                return None;
            }
            Some(p.file_stem()?.to_str()?.to_string())
        })
        .collect();
    actual.sort();

    let n = actual.len();
    for (path, text) in [
        (
            "docs/fault-model.md",
            include_str!("../docs/fault-model.md"),
        ),
        (
            "docs/architecture.md",
            include_str!("../docs/architecture.md"),
        ),
    ] {
        assert!(
            text.contains(&format!("{n} targets")) || text.contains(&format!("targets ({n})")),
            "{path} does not state the real fuzz-target count ({n}); a target was \
             added or removed without updating the docs that advertise it"
        );
    }

    // fault-model.md also enumerates them. The prose uses deliberate shorthand
    // (`sdp` for sdp_parser, `websocket` for websocket_frame), so matching
    // names one-to-one would be brittle and would rot the first time a target
    // is called something like `foo_decoder`. The durable invariant is that the
    // list is as long as the directory: that catches a target added with the
    // count bumped but the list left short, which is the realistic mistake.
    let fault = include_str!("../docs/fault-model.md");
    let listed = fault
        .split_once("targets:")
        .and_then(|(_, rest)| rest.split_once('.'))
        .map(|(list, _)| list.split(',').filter(|s| !s.trim().is_empty()).count())
        .expect("docs/fault-model.md no longer enumerates the fuzz targets after 'targets:'");
    assert_eq!(
        listed, n,
        "docs/fault-model.md names {listed} fuzz targets but {n} exist in \
         fuzz/fuzz_targets/ — the security-facing page is describing a smaller \
         fuzz surface than the tree actually has"
    );
}

/// `fuzz/Cargo.lock` pins sipnab's own version and must match the crate.
///
/// The fuzz workspace is separate, so a hand-edited version bump updates
/// `Cargo.toml`, `website/config.toml` and the man page — all of which are
/// gated — and silently leaves this one behind. It happened at 0.5.48, which
/// shipped with the lockfile still naming 0.5.47, and nothing anywhere noticed:
/// no hook, no workflow, no test looked at this file.
#[test]
fn fuzz_lockfile_pins_the_current_crate_version() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock = std::fs::read_to_string(repo.join("fuzz/Cargo.lock"))
        .expect("fuzz/Cargo.lock must exist — the fuzz workspace is committed");

    // The [[package]] block whose name is sipnab; its `version` is the pin.
    let pinned = lock
        .split("[[package]]")
        .find(|block| block.contains("name = \"sipnab\""))
        .and_then(|block| {
            block
                .lines()
                .find_map(|l| l.trim().strip_prefix("version = "))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .expect("no sipnab [[package]] entry in fuzz/Cargo.lock");

    assert_eq!(
        pinned,
        env!("CARGO_PKG_VERSION"),
        "fuzz/Cargo.lock pins sipnab {pinned} but the crate is {} — run \
         `cargo update -p sipnab --manifest-path fuzz/Cargo.toml` (or any cargo \
         command in fuzz/) and commit the result with the version bump",
        env!("CARGO_PKG_VERSION")
    );
}

/// Both benchmark pages must name the same measured release and date, and that
/// release must actually exist.
///
/// This replaces the old `current release X.Y.Z` marker, which required the
/// pages to name the crate version and so re-stamped them as current at every
/// release without anything being re-measured. What matters is not that the
/// page names today's version — it is that both trees agree on which artifact
/// produced the numbers, and that it is a real published one.
#[test]
fn benchmark_pages_agree_on_what_was_measured() {
    let re = regex::Regex::new(
        r"released (\d+\.\d+\.\d+) artifact, checksum-verified, (\d{4}-\d{2}-\d{2})",
    )
    .unwrap();

    let mut seen: Option<(String, String)> = None;
    for (path, text) in [
        ("docs/benchmarks.md", include_str!("../docs/benchmarks.md")),
        (
            "website/content/docs/benchmarks.md",
            include_str!("../website/content/docs/benchmarks.md"),
        ),
    ] {
        let cap = re.captures(text).unwrap_or_else(|| {
            panic!(
                "{path}: no 'released X.Y.Z artifact, checksum-verified, YYYY-MM-DD' \
                 statement. Every number on this page comes from one artifact on one \
                 day; if the page will not say which, the numbers are unattributable."
            )
        });
        let found = (cap[1].to_string(), cap[2].to_string());
        match &seen {
            None => seen = Some(found),
            Some(first) => assert_eq!(
                first, &found,
                "the two benchmark pages disagree about what was measured \
                 ({first:?} vs {found:?}) — a re-benchmark must update both trees"
            ),
        }
    }

    // You cannot have measured a release that does not exist yet.
    let (measured, _) = seen.expect("at least one benchmarks page");
    let crate_version = env!("CARGO_PKG_VERSION");
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|p| p.parse().unwrap()).collect() };
    assert!(
        parse(&measured) <= parse(crate_version),
        "benchmarks claim to be measured on {measured}, which is newer than the \
         crate version {crate_version}"
    );
}

/// The benchmark harness the benchmarks page cites must exist in the repo.
///
/// From 0.5.18 to 0.5.46 the page claimed "every number here is reproducible"
/// and called the listed commands "the full recipe", while the corpus generator
/// sat in an unpublished repository. Nobody could re-run a single number,
/// including on the reference host the methodology names. Nothing detected it
/// because nothing looked.
#[test]
fn benchmark_harness_is_published() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for f in [
        "bench/carrier.py",
        "bench/scaling.sh",
        "bench/compare.sh",
        "bench/README.md",
    ] {
        assert!(
            repo.join(f).is_file(),
            "{f} is missing, but docs/benchmarks.md tells readers to run it. \
             A reproducibility claim whose harness is absent is not a claim."
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["bench/scaling.sh", "bench/compare.sh"] {
            let mode = std::fs::metadata(repo.join(f))
                .expect("harness script metadata")
                .permissions()
                .mode();
            assert!(
                mode & 0o111 != 0,
                "{f} is not executable, so the documented `bench/…` invocation fails"
            );
        }
    }
}

/// The corpus figures quoted on the benchmarks page must be what the generator
/// actually produces.
///
/// The page names an exact composition — 535,000 packets, 35,000 SIP, 500,000
/// RTP, 93.5% — and readers use those to confirm they rebuilt the right corpus.
/// Generating the full 128 MB in a unit test would be wasteful, so this runs a
/// 1/100-scale corpus and requires it to scale exactly. Change the packet mix
/// and this fails rather than letting the page describe a corpus that no longer
/// exists.
#[test]
fn carrier_generator_produces_the_documented_corpus() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = std::env::temp_dir().join(format!("sipnab-carrier-{}.pcap", std::process::id()));

    let out = std::process::Command::new("python3")
        .arg(repo.join("bench/carrier.py"))
        .args(["--calls", "50", "--quiet", "--out"])
        .arg(&tmp)
        .current_dir(repo)
        .output()
        .expect("run bench/carrier.py — python3 must be on PATH");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "bench/carrier.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 50 calls is exactly 1/100 of the documented corpus, so the sample's
    // composition must be the published one divided by 100.
    let summary = String::from_utf8_lossy(&out.stdout);
    let expected = "5350 packets (350 SIP, 5000 RTP = 93.5%), 50 calls";
    assert!(
        summary.contains(expected),
        "bench/carrier.py no longer produces the documented packet mix.\n  \
         expected to contain: {expected}\n  got: {}",
        summary.trim()
    );

    // …and the page must still quote the 100x figures that sample implies.
    for doc in [
        include_str!("../docs/benchmarks.md"),
        include_str!("../website/content/docs/benchmarks.md"),
    ] {
        for claim in ["535,000 packets", "35,000 SIP", "500,000 RTP", "93.5%"] {
            assert!(
                doc.contains(claim),
                "benchmarks page no longer states {claim:?}, but bench/carrier.py \
                 still produces it at --calls 5000 (100x the generated sample)"
            );
        }
    }
}

/// Every `[features]` key in Cargo.toml must appear in the README feature
/// table. `metrics` is a DEFAULT feature that was absent for several
/// releases, so a reader could not discover it existed.
#[test]
fn readme_feature_table_covers_every_cargo_feature() {
    let manifest = include_str!("../Cargo.toml");
    let readme = include_str!("../README.md");

    let features_block = manifest
        .split("[features]")
        .nth(1)
        .expect("Cargo.toml has a [features] section")
        .split("\n[")
        .next()
        .expect("features section terminates");

    let mut missing = Vec::new();
    let mut seen = 0;
    for line in features_block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, _)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name == "default" {
            continue;
        }
        seen += 1;
        if !readme.contains(&format!("`{name}`")) {
            missing.push(name.to_string());
        }
    }

    assert_eq!(
        seen, 12,
        "feature extraction found {seen} features, expected 12. Bump when a \
         feature is added; a drop means the parser stopped reading Cargo.toml's \
         table and the comparison below narrowed."
    );
    assert!(
        missing.is_empty(),
        "README feature table is missing: {}",
        missing.join(", ")
    );
}

/// Every `[theme]` color slot must be documented in both theme guides, and the
/// slot count quoted in both config references must match `ThemeConfig`.
///
/// This closes a drift that shipped: `status_bg` is applied by
/// `tui::theme::apply_color` and has a dedicated round-trip test, yet both
/// theme guides told readers it was "not configurable", and the two config
/// references disagreed on the slot count (11 vs 10).
#[test]
fn theme_slots_are_documented_and_counted_correctly() {
    let config_rs = include_str!("../src/config.rs");

    // Fields of `pub struct ThemeConfig` — the authoritative slot list.
    let block = config_rs
        .split("pub struct ThemeConfig {")
        .nth(1)
        .expect("ThemeConfig struct not found")
        .split("\n}")
        .next()
        .expect("unterminated ThemeConfig struct");
    let slots: Vec<&str> = block
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();

    assert_eq!(
        slots.len(),
        12,
        "ThemeConfig field extraction found {} slots, expected 12. Bump when a \
         slot is added; a drop means the parser stopped reading the struct and \
         the documentation comparison below narrowed with it.",
        slots.len()
    );

    // `highlight` is a legacy alias for `selected`, counted separately in prose.
    let semantic = slots.len() - 1;

    let guides: &[(&str, &str)] = &[
        (
            "docs/theme-guide.md",
            include_str!("../docs/theme-guide.md"),
        ),
        (
            "website/content/docs/theme.md",
            include_str!("../website/content/docs/theme.md"),
        ),
    ];
    let mut missing = Vec::new();
    for (name, text) in guides {
        for slot in &slots {
            if !text.contains(&format!("`{slot}`")) {
                missing.push(format!("{name}: `{slot}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "theme guides do not document every [theme] slot:\n  {}",
        missing.join("\n  ")
    );

    let refs: &[(&str, &str)] = &[
        (
            "docs/config-reference.md",
            include_str!("../docs/config-reference.md"),
        ),
        (
            "website/content/docs/config.md",
            include_str!("../website/content/docs/config.md"),
        ),
    ];
    let expected = format!("{semantic} semantic color slots");
    let mut wrong = Vec::new();
    for (name, text) in refs {
        if !text.contains(&expected) {
            wrong.push(name.to_string());
        }
    }
    assert!(
        wrong.is_empty(),
        "these config references do not say \"{expected}\" (ThemeConfig has \
         {} fields, one of which is the `highlight` alias): {}",
        slots.len(),
        wrong.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Third-party notices: attribution is an obligation, and a stale file is a
// broken one.
// ---------------------------------------------------------------------------

/// `THIRD-PARTY-NOTICES.md` equals what the generator produces from the real
/// dependency graph today.
///
/// MIT and Apache-2.0 both require the notice to travel with the binary, and
/// libasound is LGPL-2.1-or-later, so this file is a licence obligation rather
/// than a courtesy. Hand-maintained it would go stale on the first
/// `cargo update` with nothing to notice — the same shape as every other gap
/// this suite exists for, except the consequence is legal rather than cosmetic.
#[test]
fn third_party_notices_are_current() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = std::env::temp_dir().join(format!("sipnab-notices-{}.md", std::process::id()));

    let out = std::process::Command::new("python3")
        .arg(repo.join("scripts/build-third-party-notices.py"))
        .arg(&tmp)
        .current_dir(repo)
        .output()
        .expect("run scripts/build-third-party-notices.py — python3 and cargo must be on PATH");
    assert!(
        out.status.success(),
        "build-third-party-notices.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let fresh = std::fs::read_to_string(&tmp).expect("generated notices");
    let committed =
        std::fs::read_to_string(repo.join("THIRD-PARTY-NOTICES.md")).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);

    assert_eq!(
        fresh.trim_end(),
        committed.trim_end(),
        "THIRD-PARTY-NOTICES.md is stale — the dependency graph changed. \
         Regenerate with `python3 scripts/build-third-party-notices.py` and commit."
    );
}

/// The notices name every system library the released binaries link, with the
/// licence that actually applies.
///
/// These are resolved by the host's package manager, never by cargo, so they
/// cannot be derived from the lockfile and cannot be caught by the currency
/// check above. libasound is the only copyleft component sipnab touches; if its
/// entry ever disappears, the notice obligation is silently unmet.
#[test]
fn third_party_notices_cover_system_libraries() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let notices = std::fs::read_to_string(repo.join("THIRD-PARTY-NOTICES.md"))
        .expect("THIRD-PARTY-NOTICES.md must exist — it ships in every release artifact");

    for (lib, licence) in [
        ("libpcap", "BSD-3-Clause"),
        ("libasound", "LGPL-2.1-or-later"),
    ] {
        assert!(
            notices.contains(lib),
            "THIRD-PARTY-NOTICES.md does not mention {lib}, which the released \
             binaries link at runtime"
        );
        assert!(
            notices.contains(licence),
            "THIRD-PARTY-NOTICES.md does not state {licence} (for {lib})"
        );
    }

    // The notices are worthless if they do not ship. Every release artifact
    // that carries LICENSE-MIT must carry these too.
    let release = std::fs::read_to_string(repo.join(".github/workflows/release.yml"))
        .expect("read release.yml");
    assert!(
        release.contains("THIRD-PARTY-NOTICES.md"),
        "release.yml does not package THIRD-PARTY-NOTICES.md — the notices would \
         exist in the repository and reach nobody who downloads a binary"
    );
}

/// The MCP tool table must list every tool the server registers.
///
/// `docs/mcp.md`'s table listed seven; the server registers eleven. The three
/// missing ones — `search_messages`, `tail_dialogs`, `security_findings` —
/// were documented in the prose below it, so nothing was factually wrong and
/// no link was dead. A reader scanning the table for what MCP can do simply
/// would not have learned they exist. (`stats` was missing from both copies of
/// the page until the merge.)
///
/// Ground truth is the `#[tool(name = "…")]` attributes, not a second list.
#[test]
fn mcp_tool_table_lists_every_registered_tool() {
    let server = std::fs::read_to_string("src/mcp/server.rs").expect("src/mcp/server.rs");
    let registered: BTreeSet<String> = regex::Regex::new(r#"name = "([a-z_]+)""#)
        .expect("regex")
        .captures_iter(&server)
        .map(|c| c[1].to_string())
        .collect();
    // Raised 29 -> 30 by `save_findings`, the first write verb on this surface.
    // Raised 31 -> 32 by `show_evidence`, which follows a frame pointer back
    // to the bytes it names — the half of #128 that makes a `frame_ref` on a
    // fact something a caller can actually check.
    // Raised 30 -> 31 by `find_correlated`, which exposes the multi-leg
    // correlation engine that had existed in DialogStore with no way to reach it.
    assert_eq!(
        registered.len(),
        32,
        "found only {} #[tool(name = ...)] entries in src/mcp/server.rs — the \
         attribute shape changed and this test is no longer reading the \
         registry: {registered:?}",
        registered.len()
    );

    let doc = std::fs::read_to_string("docs/mcp.md").expect("docs/mcp.md");
    let table = doc
        .split_once("| Tool | Parameters | Returns |")
        .expect("docs/mcp.md has no tool table")
        .1;
    let table = &table[..table.find("\n\n").unwrap_or(table.len())];
    let documented: BTreeSet<String> = regex::RegexBuilder::new(r"^\| `([a-z_]+)`")
        .multi_line(true)
        .build()
        .expect("regex")
        .captures_iter(table)
        .map(|c| c[1].to_string())
        .collect();

    let missing: Vec<_> = registered.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "these MCP tools are registered but absent from the table in \
         docs/mcp.md: {missing:?}"
    );
    let phantom: Vec<_> = documented.difference(&registered).collect();
    assert!(
        phantom.is_empty(),
        "docs/mcp.md documents MCP tools the server does not register: \
         {phantom:?}"
    );
}

// ---------------------------------------------------------------------------
// One fenced shell block is one clipboard payload.
//
// Every surface that publishes these files puts a single copy button on a
// fence and hands over the whole body: the site does it in
// website/templates/page.html:98 (`code.innerText`), and GitHub does it for
// docs/**, README.md and the wiki with its own button. A repository cannot
// influence GitHub's — class, data-*, <button> and <script> are all stripped
// from rendered markdown — so the only lever with three-of-three reach is the
// bytes inside the fence.
//
// A block holding two independent recipes therefore hands the reader both.
// They asked for one, they get two, and they believe they ran one. That is
// merely untidy for a `sipnab --json | jq` pair; it is an incident when the
// extra command writes: `openssl rand -hex 32 > /etc/sipnab/mcp-token`
// destroys a live MCP bearer token, after which the server serves a secret no
// configured agent has.
// ---------------------------------------------------------------------------

const SHELL_LANGS: &[&str] = &["bash", "sh", "shell", "console", "zsh"];

// SCOPE, stated because the gap is real and a reader should not assume
// otherwise: this gate reads fences whose info string names a shell. The site
// attaches its copy button to every `pre` (website/templates/page.html:90), so
// an UNLABELED fence gets a button too, and 230 of those exist in the scanned
// corpus — 132 of them command-looking. They are not checked.
//
// Scanning them by heuristic was rejected: "starts with a command-looking
// word" also matches terminal transcripts and output samples, and a gate that
// cries wolf gets muted, which is worse than one with a stated limit. Closing
// this properly means labelling those fences, which is a remediation of its
// own, not a condition of this gate.

/// First line of a block that declares itself one ordered procedure.
const SEQUENCE_MARKER: &str = "# Run all of these, in order.";

/// `(1-based line of the opening fence, info word, body)` for every fenced
/// block, tracking fence character and length so a nested ```` ```markdown ````
/// sample does not corrupt the walk.
fn fenced_with_info(text: &str) -> Vec<(usize, String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let ch = if t.starts_with("```") {
            '`'
        } else if t.starts_with("~~~") {
            '~'
        } else {
            i += 1;
            continue;
        };
        let n = t.chars().take_while(|c| *c == ch).count();
        let info = t[n..].trim().to_string();
        // A closing fence carries no info string; an info string means opening.
        let start = i;
        let mut body = String::new();
        i += 1;
        while i < lines.len() {
            let c = lines[i].trim_start();
            if c.starts_with(&ch.to_string().repeat(n)) && c[n..].trim().is_empty() {
                break;
            }
            body.push_str(lines[i]);
            body.push('\n');
            i += 1;
        }
        i += 1;
        let word = info.split_whitespace().next().unwrap_or("").to_lowercase();
        out.push((start + 1, word, body));
    }
    out
}

/// The top-level command units in a shell fence body.
///
/// A line does not start a new unit when the previous one continues into it:
/// a trailing `\`, a quote left open across the newline, an open heredoc, or a
/// trailing `|`, `&&`, `||` or `&`. Blank and `#`-comment lines are not units.
///
/// Quote state is carried ACROSS physical lines, deliberately. Resetting it
/// per line reads the prose inside `git commit -m "…"` as separate commands,
/// which is the same mistake a blank-line heuristic makes — and a gate that
/// cries wolf gets muted, which is worse than no gate.
///
/// Heredocs are handled as prevention rather than a fix: the scanned corpus
/// contains none today, and they are the one construct that would otherwise
/// make this gate report a multi-line document body as many commands.
fn command_units(body: &str) -> Vec<String> {
    let mut starts = Vec::new();
    let mut pending = false;
    let mut here: Option<String> = None;
    let mut quote: Option<char> = None;

    for raw in body.lines() {
        if let Some(tag) = &here {
            if raw.trim() == tag.trim() {
                here = None;
            }
            continue;
        }
        let stripped = raw.trim();
        if quote.is_none() && !pending && (stripped.is_empty() || stripped.starts_with('#')) {
            continue;
        }
        if quote.is_none() && !pending {
            starts.push(raw.to_string());
        }

        // Rescan the line to carry quote state forward.
        let mut q = quote;
        let mut esc = false;
        let chars: Vec<char> = raw.chars().collect();
        for (idx, c) in chars.iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match q {
                None => {
                    if *c == '\\' {
                        esc = true;
                    } else if *c == '\'' || *c == '"' {
                        q = Some(*c);
                    } else if *c == '#' && (idx == 0 || chars[idx - 1].is_whitespace()) {
                        break;
                    }
                }
                Some('\'') => {
                    if *c == '\'' {
                        q = None;
                    }
                }
                Some(_) => {
                    if *c == '\\' {
                        esc = true;
                    } else if *c == '"' {
                        q = None;
                    }
                }
            }
        }
        quote = q;

        if quote.is_none() {
            let rt = raw.trim_end();
            // `<<<` is a herestring, not a heredoc: it takes no terminator, so
            // treating it as one would swallow the rest of the block.
            if !rt.contains("<<<")
                && let Some(caps) = heredoc_re().captures(rt)
            {
                here = Some(caps[1].to_string());
            }
            pending = rt.ends_with('\\')
                || rt.ends_with('|')
                || rt.ends_with("&&")
                || rt.ends_with("||")
                || rt.ends_with('&');
        } else {
            pending = false;
        }
    }
    starts
}

fn heredoc_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)"#).unwrap())
}

/// Markdown the gate scans: every **tracked** `*.md`, minus planning trees
/// and minus generated mirrors.
///
/// The file list comes from `git ls-files` rather than a directory walk, so
/// build output and scratch are excluded by definition instead of by a
/// hand-kept skip list. A walk initially reported 205 offenders against
/// `git`'s 135, the difference being `build/wiki/` — `scripts/build-wiki.py`'s
/// gitignored output — and later `.superpowers/`. Each would have been a new
/// entry in a list that only grows, and each double-reports a defect whose
/// only real fix is in `docs/`.
///
/// Mirrors are excluded rather than forgiven. Both site generators' `render()`
/// rewrites links and prepends front matter; fence bodies pass through
/// byte-identically, and that identity is gated by
/// `site_pages_mirror_is_current`. So fixing `docs/examples.md` and
/// regenerating is the only way the mirror can be green — coverage is
/// transitive and stricter than scanning it directly. Reporting the mirror
/// would point the author at a file whose own header says "do not edit".
fn scanned_markdown() -> Vec<std::path::PathBuf> {
    // Planning material, never published. Retro-editing a historical record to
    // satisfy a rendering gate would corrupt it. Same exclusion and reason as
    // link_integrity_test's docs-tree scan.
    const SKIP_DIRS: &[&str] = &["docs/superpowers/", "docs/design/", "docs/research/"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|rel| !SKIP_DIRS.iter().any(|d| rel.starts_with(d)))
        .map(|rel| root.join(rel))
        .collect()
}

/// A fenced shell block must hand the reader exactly one command, unless it
/// declares itself an ordered procedure.
#[test]
fn shell_fence_is_one_clipboard_payload() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let mut offenders = Vec::new();
    let mut scanned = 0;

    for path in scanned_markdown() {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("Generated by scripts/build-site") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        for (line, info, body) in fenced_with_info(&text) {
            if !SHELL_LANGS.contains(&info.as_str()) {
                continue;
            }
            scanned += 1;
            let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if first.trim() == SEQUENCE_MARKER {
                continue;
            }
            let units = command_units(&body);
            if units.len() > 1 {
                offenders.push(format!(
                    "{rel}:{line}: one copy button hands the reader {} commands:\n      {}",
                    units.len(),
                    units
                        .iter()
                        .map(|u| u.trim().to_string())
                        .collect::<Vec<_>>()
                        .join("\n      ")
                ));
            }
        }
    }

    assert!(
        scanned >= 300,
        "only {scanned} shell fences scanned (346 at the time of writing) — the \
         walk or the fence parser stopped matching, and this gate is reporting a \
         safety it is not providing"
    );
    assert!(
        offenders.is_empty(),
        "shell fences whose single copy button hands the reader more than one \
         command — the reader believes they ran one:\n  {}\n\n\
         Fix at the source:\n  \
         - alternatives  -> one fenced block each, so each gets its own copy button\n  \
         - one procedure -> add `{SEQUENCE_MARKER}` as the first line\n  \
         - dense catalog -> drop the fence; a markdown list with inline `code` \
         has no copy button on any surface\n  \
         (Never edit a website/content/docs page carrying the generator banner \
         — fix docs/ and re-run scripts/build-site-pages.py.)\n\n\
         Scope: this asserts the button hands over exactly ONE command. It does \
         NOT assert that command is correct or safe.",
        offenders.join("\n  ")
    );
}

/// The corpus scan goes green the moment the docs are fixed, so these pin the
/// lexer itself against the defect that motivated it. Without them,
/// `command_units` could be softened to always return one unit and every gate
/// above would still pass.
#[test]
fn command_units_splits_the_shipped_two_command_block() {
    // docs/troubleshooting.md:9 as published in v0.5.55 — the block whose
    // copy button handed the reader a --call-report that wrote report.md they
    // never asked for.
    let body = "\
# All failed calls: Call-ID + response code + reason per response message
sipnab -N -I capture.pcap --filter \"state == 'Failed'\" --json \\
  | jq -c 'select(.is_request == false) | {call_id, status_code, reason}'

# Detailed report for one call (Markdown, ready for a ticket)
sipnab -I capture.pcap --call-report \"abc123@host\" --markdown > report.md
";
    let units = command_units(body);
    assert_eq!(
        units.len(),
        2,
        "the shipped two-command block must read as 2 units, got {}: {units:#?}",
        units.len()
    );
}

#[test]
fn command_units_joins_continuations_quotes_and_heredocs() {
    // Trailing backslash.
    assert_eq!(
        command_units("sipnab -N \\\n  --json \\\n  -I x.pcap\n").len(),
        1
    );
    // Pipe into a continued expression.
    assert_eq!(
        command_units("sipnab -N --json |\n  jq .call_id\n").len(),
        1
    );
    // && chain.
    assert_eq!(command_units("cd /tmp &&\n  ls\n").len(), 1);
    // A quote left open across lines: the prose inside is NOT a command. This
    // is the case a blank-line heuristic gets wrong.
    assert_eq!(
        command_units("git commit -m \"line one\n\nline two\n\nline three\"\n").len(),
        1,
        "quote state must carry across newlines"
    );
    // Heredoc body is not a series of commands.
    assert_eq!(
        command_units("cat <<'EOF' > /tmp/f\nalpha\nbeta\nEOF\n").len(),
        1
    );
    // A herestring is not a heredoc.
    assert_eq!(command_units("jq . <<< \"$x\"\necho done\n").len(), 2);
    // Comments and blanks are not units.
    assert_eq!(command_units("# just a note\n\n# another\n").len(), 0);
}

#[test]
fn sequence_marker_admits_a_declared_procedure() {
    let body = format!(
        "{SEQUENCE_MARKER}\nmkdir -p /etc/sipnab\nopenssl rand -hex 32 > /etc/sipnab/mcp-token\nchmod 0600 /etc/sipnab/mcp-token\n"
    );
    assert!(
        command_units(&body).len() > 1,
        "the procedure genuinely holds several commands"
    );
    let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    assert_eq!(
        first.trim(),
        SEQUENCE_MARKER,
        "and the gate admits it on the strength of the declaration alone"
    );
}

/// No documentation table repeats a row.
///
/// `THIRD-PARTY-NOTICES.md` listed `r-efi` twice under "Multi-licensed crates
/// and the licence elected". The generator deduplicated with
/// `set((name, version, licence))` and then emitted a row *without* the
/// version, so a crate vendored at two versions — r-efi at 5.3.0 and 6.0.0 —
/// passed the set as two distinct tuples and printed one identical row twice.
///
/// The shape generalises past that one file: a table row is a claim, and the
/// same claim made twice is either a copy-paste artifact or a key that dropped
/// the column distinguishing it. Neither is something a reader should have to
/// resolve, so this sweeps every tracked markdown file rather than the one
/// that happened to break.
///
/// Rows inside code fences are excluded — a fenced example may legitimately
/// show a repeated line.
#[test]
fn no_documentation_table_repeats_a_row() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "*.md"])
        .current_dir(repo)
        .output()
        .expect("git ls-files");
    let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    // Pinned. `>= 50` against a real 93 let the sweep lose nearly half the
    // tracked markdown without noticing, which for a duplicate-row check means
    // the duplicates it exists to find simply stop being looked for.
    // Raised 123 -> 124 by `docs/design/capture-tuning-tasks.md`, which two
    // tracked design docs already link to and so cannot stay untracked, and
    // 124 -> 125 by `website/content/docs/tuning-capture.md`, the site mirror
    // of the new tuning page.
    // 125 -> 127 by `CLA.md` (the Contributor License Agreement, also the gist
    // source) and `website/content/cla.md` (the sipnab.com/cla/ page).
    // Raised 130 -> 131 by `docs/design/icid-correlation.md`, the
    // P-Charging-Vector `icid-value` correlation spec. A design doc has no site
    // mirror, so it costs this counter one file and not two. The number is the
    // one this gate reported on a failing run, not one added up by hand.
    assert_eq!(
        files.len(),
        131,
        "found {} tracked markdown files, expected 131. More is fine — bump \
         this. FEWER means the sweep stopped reading part of the tree and this \
         gate narrowed silently.",
        files.len()
    );

    let mut offenders = Vec::new();
    let mut tables = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
        // Blank fenced blocks so an example that repeats a line is not a
        // finding, then walk consecutive `|` lines as one table.
        let scanned = markdown::blank_fences(&text);
        let lines: Vec<&str> = scanned.lines().collect();
        let mut table: Vec<(usize, &str)> = Vec::new();
        for (n, line) in lines
            .iter()
            .enumerate()
            .chain(std::iter::once((lines.len(), &"")))
        {
            let l = line.trim();
            if l.starts_with('|') {
                table.push((n + 1, l));
                continue;
            }
            if table.len() > 2 {
                tables += 1;
                for i in 0..table.len() {
                    // A separator row (`|---|---|`) legitimately repeats
                    // across tables but never within one.
                    if table[i].1.chars().all(|c| "|-: ".contains(c)) {
                        continue;
                    }
                    if let Some(j) = (0..i).find(|j| table[*j].1 == table[i].1) {
                        offenders.push(format!(
                            "{file}:{} duplicates line {}: {}",
                            table[i].0, table[j].0, table[i].1
                        ));
                    }
                }
            }
            table.clear();
        }
    }
    // Pinned. `>= 40` against a real 292 is the widest gap of the set: 250
    // tables could stop being walked and the gate would still report the
    // documentation as scanned.
    // Raised 437 -> 448 by the capture-tuning work, diffed file by file against
    // the merge base rather than guessed: `docs/tuning-capture.md` +4 and its
    // generated site mirror +4 (the same four pages twice, which is what a
    // mirrored page costs this counter),
    // `docs/design/process-isolation-and-hot-path-cost.md` +2 and
    // `docs/design/capture-tuning-tasks.md` +1. Nothing else moved: the pages
    // this cycle edited most heavily — `rest-api.md`, `mcp.md`,
    // `THIRD-PARTY-NOTICES.md` — grew ROWS inside tables that already existed,
    // which this gate does not count.
    // Raised 448 -> 454 by `docs/encapsulations.md`, counted rather than
    // guessed: three tables on the page (link types, EtherTypes, tunnels above
    // the link layer) and three in its generated site mirror — the same page
    // twice, which is what a mirrored page costs this counter, exactly as the
    // tuning-capture entry above records.
    // Raised 454 -> 460 by the `capture_health` MCP tool, counted rather than
    // guessed: three tables in its `docs/mcp.md` section (the parameter, the
    // `attachment` codes, the `undecodable_by_reason` codes) and three in the
    // generated site mirror — the same page twice, which is what a mirrored
    // page costs this counter, exactly as the two entries above record. The
    // tool-table row it also adds grew a table that already existed, which
    // this gate does not count.
    // Raised 460 -> 462 by the "three shapes" table in
    // `docs/mcp-walkthrough.md`, counted rather than guessed: one table there
    // and one in the generated site mirror — the same page twice, which is what
    // a mirrored page costs this counter, exactly as the entries above record.
    // It replaced a bullet list with a table so each shape could link to the
    // section that documents it, which is why this is +2 and not +1 per shape.
    // Raised 462 -> 464 by the four-strategy correlation table in
    // `docs/internals/domain-primer.md`: one table there and one in the
    // generated site mirror, the same page twice, as the entries above record.
    // Raised 464 -> 466 by `find_correlated`'s strategy table in docs/mcp.md:
    // one there and one in the site mirror, the same page twice.
    // Raised 466 -> 470 by the federated-tracing section in
    // docs/mcp-walkthrough.md: a strategy table and a federated-vs-centralised
    // table, each doubled by the site mirror.
    // Raised 470 -> 472 by the untrusted-capture-text section in docs/mcp.md
    // (#139): one fenced/verbatim table per surface, doubled by the site mirror.
    // Raised 472 -> 474 by the write-verb table in docs/mcp.md's "What the
    // write verbs do" section (#146): one table plus the site mirror.
    // Raised 475 -> 477 by the `show_evidence` status table (one per doc
    // mirror), which spells out that verified / unverified / unresolvable are
    // three different claims rather than degrees of the same one.
    // Raised 474 -> 475 by the "What shipped" table added to §2 of
    // docs/design/deferred-and-declined.md, which had been describing
    // save_findings and CaptureEtag as pending after both had shipped. That
    // page has no site mirror, so it counts once.
    //
    // The three entries above landed on two branches that were merged: the
    // first two on main, the third on the stale-documentation sweep. Neither
    // side's total was right for the merged tree, so this number was taken
    // from a clean run rather than added up.
    // Raised 479 -> 487 by the three design specs (live-fanout, syscall-sandbox,
    // mid-dialog-state-machine). Previously raised 477 -> 479 by the "I want to"
    // goal index added to the top of
    // docs/install.md, which the project's own task-first rule requires of
    // every how-to page. That page HAS a site mirror, so one authored table
    // counts twice.
    // Raised 487 -> 493 by the B2BUA-correlation and scripted-client work in
    // docs/mcp-walkthrough.md, taken from this gate's own count rather than
    // added up: three NEW tables (the four fields to read off `find_correlated`,
    // which responses carry `capture_identity`, and the HTTP-status decoder for
    // the script), each doubled by the site mirror. The strategy table on that
    // page grew a `via_branch` row and a fourth column, which is growth inside a
    // table that already existed and so does not count here.
    //
    // Raised again by docs/design/icid-correlation.md, the P-Charging-Vector
    // `icid-value` correlation spec: eight authored tables on one page (the five
    // existing strategies, the RFCs updating RFC 7315, what a plain icid match
    // means per hop, where the header is present per hop, the two proposed
    // reasons, the parameters that must never be surfaced, the files a new
    // strategy touches, and how a fixture denies each existing strategy). A
    // design doc has no site mirror, so each counts ONCE — unlike the mirrored
    // pages above, which cost two apiece.
    //
    // Those two landed on separate branches, and neither side's total was right
    // for the merged tree. As with the 479 entry above, this number was taken
    // from a clean run of this gate rather than added up.
    //
    // Raised 501 -> 502 by the 0.5.88 changelog entry, which tabulates the two
    // `P-Charging-Vector` strategies against what a match on each one actually
    // claims. CHANGELOG.md is walked by this gate and has no site mirror, so it
    // costs one. Worth knowing before writing a release entry: a table in the
    // changelog moves this ratchet exactly like a table in a doc page does.
    // Raised 502 -> 503 by PERF1's measurement table in docs/design/backlog.md,
    // which tabulates four builds against the throughput each one measured.
    // Same rule as the changelog entry above: that file is walked by this gate
    // and has no site mirror, so a table there costs one rather than two.
    // Raised 503 -> 504 by PERF1's bisect table, which records what each
    // commit measured with the digest zeroed. Same rule as the two entries
    // above: backlog.md has no site mirror, so a table there costs one.
    assert_eq!(
        tables, 504,
        "walked {tables} tables, expected 504. More is fine — bump this. FEWER \
         means the table detection stopped matching and this gate is checking \
         less than it claims."
    );
    assert!(
        offenders.is_empty(),
        "documentation tables repeat a row — either a copy-paste artifact, or a \
         key that dropped the column telling the rows apart:\n  {}",
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Task-first headings (spec: docs/design/task-first-docs.md)
// ---------------------------------------------------------------------------

/// How-to headings must name the reader's goal, and the ratio may not fall.
///
/// A user looking for "sipnab on a remote server, Claude Code on my laptop"
/// could not find it, because the section was called "Scenario 2A —
/// SSH-launched stdio: ad-hoc, zero server configuration". Accurate, and
/// useless to anyone who did not already know that "SSH-launched stdio" was the
/// thing they wanted. Measured across the three how-to pages, task-first
/// headings ran 90% / 62% / 8% — so the repo knew how to do this everywhere
/// except the newest surface, whose docs were written from the implementation
/// outward.
///
/// A **ratchet, not a threshold**, and deliberately so. Some headings are
/// legitimately nouns — "Codex CLI", "Cursor", "VS Code" are a list of clients,
/// not tasks — so no honest fixed percentage exists. What must not happen is
/// backsliding, and that is exactly what a floor per page catches.
///
/// Raising a floor after improving a page is the intended workflow. Lowering
/// one is the thing to argue about in review.
#[test]
fn how_to_headings_stay_task_first() {
    /// Verbs a reader would use for their own goal. Extend freely — a missing
    /// verb only ever understates the score, which the ratchet tolerates.
    const GOAL_VERBS: &[&str] = &[
        "alert",
        "analyse",
        "analyze",
        "ask",
        "block",
        "browse",
        "check",
        "choose",
        "collect",
        "compare",
        "configure",
        "connect",
        "decrypt",
        "detect",
        "diagnose",
        "drive",
        "exchange",
        "export",
        "feed",
        "filter",
        "find",
        "fix",
        "follow",
        "generate",
        "graph",
        "inspect",
        "install",
        "keep",
        "listen",
        "live",
        "look",
        "measure",
        "narrow",
        "open",
        "query",
        "reach",
        "read",
        "record",
        "register",
        "run",
        "save",
        "search",
        "send",
        "set",
        "stream",
        "test",
        "trace",
        "triage",
        "understand",
        "use",
        "verify",
        "watch",
        "wire",
    ];

    // (page, floor) — the measured ratio at the time of writing, as a percent.
    const PAGES: &[(&str, usize)] = &[
        ("docs/tui-walkthrough.md", 90),
        ("docs/mcp-walkthrough.md", 64),
        ("docs/examples.md", 93),
    ];

    let strip = regex::Regex::new(
        r"(?i)^(\d+[a-z]?\.\s*|Scenario\s+\d+[A-Z]?\s*[—-]\s*|Step\s+\d+\s*[—-]\s*)",
    )
    .unwrap();
    let heading = regex::Regex::new(r"(?m)^#{2,3}[ \t]+(.+?)[ \t#]*$").unwrap();

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (page, floor) in PAGES {
        let text =
            std::fs::read_to_string(repo.join(page)).unwrap_or_else(|e| panic!("read {page}: {e}"));
        let heads: Vec<String> = heading
            .captures_iter(&markdown::prose(&text))
            .map(|c| c[1].to_string())
            .collect();
        assert!(
            !heads.is_empty(),
            "{page}: no headings found — did the page move?"
        );

        let task_first = heads
            .iter()
            .filter(|h| {
                let core = strip.replace(h, "");
                core.split_whitespace()
                    .next()
                    .map(|w| {
                        let w = w.to_lowercase();
                        let w = w.trim_end_matches([':', ',']);
                        GOAL_VERBS.contains(&w)
                    })
                    .unwrap_or(false)
            })
            .count();
        let pct = task_first * 100 / heads.len();

        assert!(
            pct >= *floor,
            "{page}: {task_first}/{} headings are task-first ({pct}%), below the \
             {floor}% floor. A how-to heading names the reader's GOAL, not the \
             mechanism — \"Connect Claude Code on your laptop to sipnab on a \
             server\", not \"SSH-launched stdio\". Put the mechanism in a \
             subtitle underneath. If you genuinely improved the page, raise the \
             floor; lowering it needs an argument.",
            heads.len()
        );
    }
}

/// Omitting `-d` must be documented as platform-dependent, not "auto-detect".
///
/// On Linux the default is the `any` pseudo-device — **every** interface at
/// once, loopback included. On macOS/BSD it is libpcap's default: exactly
/// **one** interface. The reference previously said "auto-detects the default
/// interface", which reads as one interface everywhere and is wrong on Linux
/// in the direction that matters: a reader concludes they are missing loopback
/// when they are not, or on macOS that they are covered when they are not.
///
/// Both trees, because a reader lands on either.
#[test]
fn device_default_is_documented_per_platform() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for page in ["docs/cli-reference.md", "website/content/docs/cli.md"] {
        let text =
            std::fs::read_to_string(repo.join(page)).unwrap_or_else(|e| panic!("read {page}: {e}"));
        assert!(
            text.contains("`any` pseudo-device"),
            "{page}: must name the Linux default as the `any` pseudo-device"
        );
        assert!(
            text.contains("every interface at once"),
            "{page}: must say the Linux default covers every interface — \
             \"auto-detect\" reads as one"
        );
        assert!(
            text.contains("one interface"),
            "{page}: must say macOS/BSD gets a single interface, or a mac \
             reader assumes the Linux behaviour"
        );
        assert!(
            !text.contains("Auto-detects the default interface"),
            "{page}: the old wording is back — it is wrong on Linux"
        );
    }

    // The CLI help is where most people actually look.
    let cli = std::fs::read_to_string(repo.join("src/cli.rs")).expect("read cli.rs");
    assert!(
        cli.contains("ALL interfaces at once"),
        "src/cli.rs: -d help must state the Linux default captures all interfaces"
    );
}

/// The SIP parameter tables must stay consistent with what sipnab claims.
///
/// `docs/sip-parameters.md` is built from three IANA registries and carries a
/// "sipnab parses" column. Two ways that page can lie, and this covers both.
///
/// The first draft computed the column by grepping the source for each
/// parameter name and reported 41 of 204 — wrong and flattering, because `m`,
/// `code`, `alg` and `count` all occur in unrelated code. A substring match is
/// not evidence of parsing. The page now claims only what could be traced to a
/// real extraction site, and this test holds those three to their accessors:
/// if `top_via_branch` or `from_tag` were removed, the claim becomes false and
/// the build fails rather than the docs quietly overstating.
#[test]
fn sip_parameter_claims_match_the_parser() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(repo.join("docs/sip-parameters.md"))
        .expect("read docs/sip-parameters.md");
    let msg = std::fs::read_to_string(repo.join("src/sip/message.rs")).expect("read message.rs");
    let diag =
        std::fs::read_to_string(repo.join("src/sip/diagnosis.rs")).expect("read diagnosis.rs");

    // (parameter, the accessor that justifies the claim, where it lives)
    for (param, accessor, source) in [
        ("branch", "fn top_via_branch", &msg),
        ("tag", "fn from_tag", &msg),
        ("expires", "fn expiry_of", &diag),
    ] {
        assert!(
            source.contains(accessor),
            "docs/sip-parameters.md claims sipnab parses `{param}`, but \
             `{accessor}` is gone. Either restore it or drop the claim — an \
             overstated support table sends someone looking for a field that \
             is not there."
        );
    }

    // The conservative-by-construction note must survive, because the number
    // is the part a future editor is most likely to "improve" back into a grep.
    assert!(
        page.contains("substring match is not evidence of parsing"),
        "the page must keep explaining why the support column is hand-verified; \
         without it, someone recomputes it by grep and reinflates it"
    );

    // Registry sizes, pinned. A drop means the build script stopped reading a
    // registry and the page silently shrank.
    for (heading, min) in [
        ("## SIP/SIPS URI parameters (", 30),
        ("## Header field parameters (", 190),
        ("## Option tags (", 30),
    ] {
        let at = page
            .find(heading)
            .unwrap_or_else(|| panic!("missing section: {heading}"));
        let rest = &page[at + heading.len()..];
        let n: usize = rest
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        assert!(
            n >= min,
            "{heading}{n}) is below {min} — a registry probably failed to load \
             and the table shipped short"
        );
    }
}

/// Every registered MCP tool needs its own documented section with an example.
///
/// A sibling test already checks the tool TABLE lists every tool. That is an
/// index, not documentation, and the gap it left was real: `triage_call`,
/// `search_by_time`, `list_captures`, `export_capture` and `export_audio` all
/// shipped with a table row and no section. The table gate was green
/// throughout, which is why nobody noticed — a reader could see that a tool
/// existed and nothing about how to call it or how to read its answer.
///
/// So this gate asks for the two things a row cannot give: a heading naming the
/// tool, and a concrete example under it.
#[test]
fn every_mcp_tool_has_a_documented_section_with_an_example() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let server =
        std::fs::read_to_string(repo.join("src/mcp/server.rs")).expect("read src/mcp/server.rs");
    let page = std::fs::read_to_string(repo.join("docs/mcp.md")).expect("read docs/mcp.md");

    let name_re = regex::Regex::new(r#"name\s*=\s*"([a-z_]+)""#).unwrap();
    let tools: std::collections::BTreeSet<String> = name_re
        .captures_iter(&server)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        tools.len() >= 20,
        "found only {} registered tools — the attribute shape changed and this \
         gate is no longer reading the registry",
        tools.len()
    );

    // Split the page into h3 sections so an example can be attributed to the
    // tool whose heading it sits under, rather than merely existing somewhere.
    let heads: Vec<(usize, String)> = page
        .match_indices("\n### ")
        .map(|(i, _)| {
            let start = i + 1;
            let end = page[start..].find('\n').map_or(page.len(), |n| start + n);
            (start, page[start..end].to_string())
        })
        .collect();

    let mut missing_section = Vec::new();
    let mut missing_example = Vec::new();

    for tool in &tools {
        let needle = format!("`{tool}`");
        let Some(idx) = heads.iter().position(|(_, h)| h.contains(&needle)) else {
            missing_section.push(tool.clone());
            continue;
        };
        let body_start = heads[idx].0;
        let body_end = heads.get(idx + 1).map_or(page.len(), |(next, _)| *next);
        let body = &page[body_start..body_end];
        // A fenced block under the heading: the call, its response, or both.
        if !body.contains("```") {
            missing_example.push(tool.clone());
        }
    }

    assert!(
        missing_section.is_empty(),
        "these MCP tools have no `### ` section in docs/mcp.md: {missing_section:?}. \
         A table row says a tool exists; it does not say how to call it or how to \
         read the answer. Give each one a heading naming it."
    );
    assert!(
        missing_example.is_empty(),
        "these MCP tools have a section but no fenced example: {missing_example:?}. \
         Show real output — an operator reaching for a tool mid-incident needs to \
         recognise the answer, not infer its shape."
    );
}

/// Every AMR-WB number printed in `docs/mos-and-codecs.md` must match the model.
///
/// Both columns are checked against `emodel_wb`, because both were wrong when
/// first written. The `Ie,WB` values were transcribed correctly from G.113, and
/// then five of the fifteen MOS figures beside them were computed by hand and
/// rounded wrong — 19.85, 18.25 and 8.85 monotic, 15.85 and 12.65 diotic. The
/// error was small enough to read as plausible and is exactly what this page
/// exists to warn against, so the page is now derived-checked rather than
/// trusted.
#[test]
fn the_published_amr_wb_tables_match_the_model() {
    use sipnab::rtp::emodel_wb::{ListeningContext, amr_wb_ie, amr_wb_mos};

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(repo.join("docs/mos-and-codecs.md"))
        .expect("read docs/mos-and-codecs.md");

    // Rows look like: | 12.65 | 13 | 4.34 |
    let row = regex::Regex::new(r"(?m)^\| ([0-9.]+) \| ([0-9]+) \| ([0-9.]+) \|$").unwrap();

    // The monotic table is the first of the two; split on its heading so a row
    // is attributed to the right listening context.
    let split = page
        .find("### Diotic")
        .expect("the diotic heading anchors the split");
    let sections = [
        (&page[..split], ListeningContext::Monotic),
        (&page[split..], ListeningContext::Diotic),
    ];

    let mut checked = 0;
    for (text, context) in sections {
        for c in row.captures_iter(text) {
            let kbps: f64 = c[1].parse().expect("kbit/s");
            let ie: f64 = c[2].parse().expect("Ie,WB");
            let mos: f64 = c[3].parse().expect("MOS");

            let real_ie = amr_wb_ie(kbps, context).unwrap_or_else(|| {
                panic!("docs list {kbps} kbit/s for {context:?}, the model has no such row")
            });
            assert!(
                (real_ie - ie).abs() < f64::EPSILON,
                "{kbps} kbit/s {context:?}: docs say Ie,WB={ie}, model says {real_ie}"
            );

            let real_mos = amr_wb_mos(kbps, context, 0.0).expect("scorable at zero loss");
            assert!(
                (real_mos - mos).abs() < 5e-3,
                "{kbps} kbit/s {context:?}: docs say MOS={mos}, model says \
                 {real_mos:.6} (rounds to {real_mos:.2})"
            );
            checked += 1;
        }
    }

    // Nine monotic rows plus six diotic. Fewer means the regex stopped matching
    // the table and this gate silently checked nothing.
    assert_eq!(
        checked, 15,
        "expected 15 AMR-WB rows in docs/mos-and-codecs.md, matched {checked}. \
         More is fine — bump this. FEWER means the table shape changed and the \
         gate is no longer reading it."
    );
}

/// Every alias the documentation spells out in full must expand to exactly what
/// `expand_alias` returns.
///
/// `problems` is the one alias documented verbatim, in `docs/examples.md` and
/// its site mirror `website/content/docs/cookbook.md`, precisely because a
/// reader is told not to conflate it with the narrower `--problems` flag. That
/// makes the quoted expansion load-bearing, and it had drifted: both files
/// listed `OR rtp.orphaned == true`, a field withdrawn from the DSL, so the
/// docs promised a broader sweep than the code performs AND named a field that
/// `--filter` now refuses outright.
///
/// Nothing caught it. `rtp_orphaned_is_refused_with_a_reason` in `src/sip/dsl.rs`
/// pins the refusal and `expand_alias`'s own test pins that the alias does not
/// contain "orphaned", but neither reads the documentation. This does.
#[test]
fn a_documented_alias_expands_to_what_the_code_expands_it_to() {
    let want = sipnab::sip::dsl::expand_alias("problems").expect("the problems alias exists");
    let normalise = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let want = normalise(want);

    let mut checked = 0;
    for rel in ["docs/examples.md", "website/content/docs/cookbook.md"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));

        // The expansion is quoted in backticks and is the only backticked span
        // in these files that opens with the alias's first predicate.
        let opener = want
            .split(" OR ")
            .next()
            .expect("the expansion has at least one predicate");
        let found = text
            .split('`')
            .find(|span| span.trim_start().starts_with(opener))
            .unwrap_or_else(|| {
                panic!(
                    "{rel} no longer quotes the `problems` expansion (nothing \
                     backticked starts with {opener:?}). If the documentation \
                     stopped spelling the alias out, delete this gate rather \
                     than letting it pass by finding nothing."
                )
            });

        assert_eq!(
            normalise(found),
            want,
            "{rel} documents the `problems` alias as expanding differently from \
             `expand_alias`. A reader building on the quoted expression gets a \
             different set of dialogs than `--filter problems` returns."
        );
        checked += 1;
    }

    assert_eq!(checked, 2, "both the doc and its site mirror must be read");
}
