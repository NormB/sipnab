// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn documented_config_samples_parse_and_validate() {
    let blocks = toml_blocks(CONFIG_REFERENCE);
    assert!(
        blocks.len() >= 5,
        "expected several documented config samples, found {}",
        blocks.len()
    );

    for (line, body) in &blocks {
        let where_ = format!("docs/config-reference.md:{line}");

        // Load through the real loader (parse + validate), exactly as sipnab
        // would at startup, by writing the sample to a temp file.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.toml");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        drop(f);

        let path_str = path.to_str().expect("temp path is utf-8");
        let loaded = sipnab::config::Config::load(Some(path_str), false).unwrap_or_else(|e| {
            panic!(
                "config sample at {where_} failed to load (parse/validate):\n{body}\nerror: {e}"
            );
        });
        // The limits section carries its own semantic validation.
        loaded.config.limits.validate().unwrap_or_else(|e| {
            panic!("config sample at {where_} limits failed validation:\n{body}\nerror: {e}");
        });

        // Loading without error is not the claim a documented example makes.
        // `Config::load` is lenient by design — it ignores unknown fields so a
        // config written for a newer version still starts — so a sample with
        // `devise` for `device`, or an invented `interfaces` key, loaded
        // cleanly and validated cleanly while the shipped binary printed
        // `WARN Unknown config key: capture.devise` and dumped an empty
        // `[capture]`. A reader copying that example got nothing, and this
        // test said the example was proven.
        let unknown = sipnab::config::Config::unknown_keys(body)
            .unwrap_or_else(|e| panic!("config sample at {where_} is not valid TOML: {e}"));
        assert!(
            unknown.is_empty(),
            "config sample at {where_} names keys sipnab does not recognize: \
             {unknown:?}\nA reader copying this gets a silent no-op — the \
             binary warns and ignores them.\n{body}"
        );
    }
}

/// The gate distinguishes a recognized key from an unrecognized one.
///
/// Without this, `unknown_keys` returning an empty vector for everything would
/// make the assertion above pass on any input, and nothing would notice.
#[test]
fn unknown_key_detection_actually_discriminates() {
    let good = "[capture]\ndevice = \"eth0\"\n";
    assert!(
        sipnab::config::Config::unknown_keys(good)
            .expect("valid toml")
            .is_empty(),
        "a recognized key must not be reported as unknown"
    );

    let typo = "[capture]\ndevise = \"eth0\"\ninterfaces = 3\n";
    let found = sipnab::config::Config::unknown_keys(typo).expect("valid toml");
    assert!(
        found.iter().any(|k| k == "capture.devise"),
        "the documented typo must be reported, got {found:?}"
    );
    assert!(
        found.iter().any(|k| k == "capture.interfaces"),
        "an invented key must be reported, got {found:?}"
    );
}
