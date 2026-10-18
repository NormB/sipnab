// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Documented config-sample validation (verification plan M-Docs — MD.4).
//!
//! Every TOML fenced block in `docs/config-reference.md` is a configuration
//! example shown to users. This test proves each one parses, passes semantic
//! validation, **and** names only keys sipnab actually recognizes — so a
//! documented example can never drift into something sipnab would reject or,
//! worse, silently ignore. (Spec §17: every documented example is executed and
//! proven.)
#![cfg(feature = "native")]

use std::io::Write;

#[path = "support/markdown.rs"]
mod markdown;

type TestError = Box<dyn std::error::Error>;

/// The full text of `docs/config-reference.md`, embedded at compile time.
const CONFIG_REFERENCE: &str = include_str!("../docs/config-reference.md");

/// The bodies of the TOML fenced blocks, in document order.
///
/// Fences come from the shared CommonMark lexer rather than a comparison
/// against the string `"```toml"`. That comparison made the exact spelling of
/// the marker the proxy for "is a config sample": breaking a sample's body to
/// invalid TOML **and adding one trailing space** to its fence marker left this
/// test green, and so did any info string — `` ```toml,ignore ``. One space was
/// the whole difference between red and green.
fn toml_blocks(md: &str) -> Vec<(usize, String)> {
    markdown::fences(md)
        .into_iter()
        .filter(|f| f.lang == "toml")
        .map(|f| (f.line, f.body))
        .collect()
}

/// Every TOML block in `docs/config-reference.md` loads, validates, and uses
/// only recognized keys.
#[test]
fn documented_config_samples_parse_and_validate() -> Result<(), TestError> {
    let blocks = toml_blocks(CONFIG_REFERENCE);
    assert!(
        blocks.len() >= 5,
        "expected several documented config samples, found {}",
        blocks.len()
    );

    let mut expanded = 0usize;
    for (line, body) in &blocks {
        let where_ = format!("docs/config-reference.md:{line}");

        // Load through the real loader (parse + validate), exactly as sipnab
        // would at startup, by writing the sample to a temp file.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sample.toml");
        let mut f = std::fs::File::create(&path)?;
        f.write_all(body.as_bytes())?;
        drop(f);

        let loaded =
            sipnab::config::Config::load_file_with_env(&path, &sample_env).map_err(|e| {
                format!(
                    "config sample at {where_} failed to load (parse/validate):\n{body}\nerror: {e}"
                )
            })?;
        if body.contains("${") {
            expanded += 1;
        }
        // The limits section carries its own semantic validation.
        loaded.limits.validate().map_err(|e| {
            format!("config sample at {where_} limits failed validation:\n{body}\nerror: {e}")
        })?;

        // Loading without error is not the claim a documented example makes.
        // `Config::load` is lenient by design — it ignores unknown fields so a
        // config written for a newer version still starts — so a sample with
        // `devise` for `device`, or an invented `interfaces` key, loaded
        // cleanly and validated cleanly while the shipped binary printed
        // `WARN Unknown config key: capture.devise` and dumped an empty
        // `[capture]`. A reader copying that example got nothing, and this
        // test said the example was proven.
        let unknown = sipnab::config::Config::unknown_keys(body)
            .map_err(|e| format!("config sample at {where_} is not valid TOML: {e}"))?;
        assert!(
            unknown.is_empty(),
            "config sample at {where_} names keys sipnab does not recognize: \
             {unknown:?}\nA reader copying this gets a silent no-op — the \
             binary warns and ignores them.\n{body}"
        );
    }
    assert!(
        expanded > 0,
        "no documented sample names a `${{NAME}}`, so the environment this \
         gate supplies is doing nothing and the expansion path is unproven"
    );
    Ok(())
}

/// TOML tables in `docs/*.md` that configure something other than sipnab, by
/// page and top-level key, with what they configure. A fence whose every
/// top-level key is listed for its page is that other tool's file and is not
/// loaded; anything else is a sipnab sample and must load.
const FOREIGN_TOML: &[(&str, &str, &str)] = &[
    ("docs/install.md", "profile", "Cargo: the release profile"),
    (
        "docs/library.md",
        "dependencies",
        "Cargo: depending on the crate",
    ),
    ("docs/plugins.md", "lib", "Cargo: the plugin's crate type"),
    (
        "docs/mcp-deploy.md",
        "mcp_servers",
        "Codex CLI: its MCP server table",
    ),
    (
        "docs/mcp-tools-security.md",
        "rules",
        "an expectation suite: the text `evaluate_expectations` takes in `rules_toml`",
    ),
];

/// Every ```` ```toml ```` fence in `docs/*.md` that is a sipnab config loads
/// through the real loader with no unknown keys.
///
/// The gate above reads `docs/config-reference.md` alone. Twelve samples on
/// other pages — the theme guide's seven themes, the `[vcon_forward]` blocks
/// of three vCon pages, `[media.codec_ie]` on the MOS page and
/// `[names.manual]` on the keybindings page — were copied by readers and
/// checked by nothing.
#[test]
fn every_sipnab_toml_sample_in_the_docs_loads() -> Result<(), TestError> {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut pages: Vec<std::path::PathBuf> = std::fs::read_dir(&docs)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    pages.sort();

    let mut loaded = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for page in &pages {
        let rel = format!(
            "docs/{}",
            page.file_name()
                .and_then(|n| n.to_str())
                .ok_or("utf-8 name")?
        );
        let text = std::fs::read_to_string(page)?;
        for (line, body) in toml_blocks(&text) {
            let where_ = format!("{rel}:{line}");
            let parsed: toml::Table = match body.parse() {
                Ok(t) => t,
                Err(e) => {
                    failures.push(format!("{where_}: a ```toml fence that is not TOML: {e}"));
                    continue;
                }
            };
            let foreign = !parsed.is_empty()
                && parsed
                    .keys()
                    .all(|k| FOREIGN_TOML.iter().any(|(p, key, _)| *p == rel && key == k));
            if foreign {
                continue;
            }
            match load_sample(&body) {
                Ok(()) => loaded += 1,
                Err(e) => failures.push(format!("{where_}: {e}\n{body}")),
            }
        }
    }
    assert!(
        // 40 when written. A floor: adding a sample never trips it.
        loaded >= 35,
        "only {loaded} sipnab samples loaded across docs/*.md: the page scan \
         stopped matching"
    );
    assert!(
        failures.is_empty(),
        "documented TOML samples a reader cannot use as written:\n{}",
        failures.join("\n")
    );
    Ok(())
}

/// Load one sample as sipnab would at startup and refuse unknown keys.
fn load_sample(body: &str) -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sample.toml");
    std::fs::write(&path, body.as_bytes())?;
    let loaded = sipnab::config::Config::load_file_with_env(&path, &sample_env)
        .map_err(|e| format!("does not load: {e}"))?;
    loaded
        .limits
        .validate()
        .map_err(|e| format!("limits do not validate: {e}"))?;
    let unknown = sipnab::config::Config::unknown_keys(body)?;
    if !unknown.is_empty() {
        return Err(format!("names keys sipnab does not recognize: {unknown:?}").into());
    }
    Ok(())
}

/// The per-sample check fails a sample the loader rejects and one with an
/// unknown key, and passes a good one, so a green gate means something.
#[test]
fn the_sample_loader_discriminates() {
    assert!(load_sample("[capture]\ndevice = \"eth0\"\n").is_ok());
    assert!(load_sample("[capture]\ndevise = \"eth0\"\n").is_err());
    assert!(load_sample("[theme]\nbackground = 7\n").is_err());
}

/// The environment a documented sample is written for.
///
/// A sample that names `${SUDO_USER}` is correct for the `sudo` invocation it
/// documents and refuses to load anywhere else — an unset variable is an
/// error by design, because an empty expansion inside a path names a real
/// directory that is not the one intended. So the gate supplies the context
/// rather than the sample avoiding one.
///
/// Written as a lookup rather than `std::env::set_var`, which would put the
/// value into shared process state that every other test in this binary sees.
fn sample_env(name: &str) -> Option<String> {
    match name {
        "SUDO_USER" => Some("norm".to_string()),
        _ => None,
    }
}

/// The documented samples really do exercise the expander.
///
/// **First of two tests owed** for the sample gate this change turned red.
/// `expanded > 0` above proves a sample carries a `${NAME}`; this proves the
/// expansion CHANGES the loaded value, so the gate cannot pass on a sample
/// whose variable was quietly left as literal text.
#[test]
fn a_documented_sample_that_names_a_variable_is_actually_expanded() -> Result<(), TestError> {
    let sample = toml_blocks(CONFIG_REFERENCE)
        .into_iter()
        .find(|(_, body)| body.contains("${"))
        .ok_or("a documented sample names a variable")?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sample.toml");
    std::fs::write(&path, sample.1.as_bytes())?;

    let loaded = sipnab::config::Config::load_file_with_env(&path, &sample_env)
        .map_err(|e| format!("the supplied environment covers this sample: {e}"))?;
    let dumped = format!("{loaded:?}");
    assert!(
        !dumped.contains("${"),
        "a variable survived unexpanded into the loaded config: {dumped}"
    );
    assert!(
        dumped.contains("norm"),
        "the supplied value did not reach the loaded config: {dumped}"
    );
    Ok(())
}

/// The default loader still reads the real environment.
///
/// **Second of two.** `load_file_with_env` exists so this gate can supply a
/// context, and that seam makes it possible for `load_file` — the one every
/// sipnab startup uses — to be wired to something that is not the environment
/// at all, with every other test here still green. `HOME` is read, never
/// written, so this stays safe to run beside anything else.
#[test]
fn the_default_loader_reads_the_real_environment() -> Result<(), TestError> {
    let Ok(home) = std::env::var("HOME") else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sample.toml");
    std::fs::write(&path, b"[capture]\ndevice = \"${HOME}\"\n")?;

    let loaded = sipnab::config::Config::load(Some(path.to_str().ok_or("utf-8 path")?), false);
    let loaded = loaded.map_err(|e| format!("HOME is set: {e}"))?;
    assert_eq!(loaded.config.capture.device.as_deref(), Some(home.as_str()));
    Ok(())
}

/// The gate distinguishes a recognized key from an unrecognized one.
///
/// Without this, `unknown_keys` returning an empty vector for everything would
/// make the assertion above pass on any input, and nothing would notice.
#[test]
fn unknown_key_detection_actually_discriminates() -> Result<(), TestError> {
    let good = "[capture]\ndevice = \"eth0\"\n";
    assert!(
        sipnab::config::Config::unknown_keys(good)
            .map_err(|e| format!("valid toml: {e}"))?
            .is_empty(),
        "a recognized key must not be reported as unknown"
    );

    let typo = "[capture]\ndevise = \"eth0\"\ninterfaces = 3\n";
    let found =
        sipnab::config::Config::unknown_keys(typo).map_err(|e| format!("valid toml: {e}"))?;
    assert!(
        found.iter().any(|k| k == "capture.devise"),
        "the documented typo must be reported, got {found:?}"
    );
    assert!(
        found.iter().any(|k| k == "capture.interfaces"),
        "an invented key must be reported, got {found:?}"
    );
    Ok(())
}
