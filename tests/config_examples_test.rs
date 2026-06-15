//! Documented config-sample validation (verification plan M-Docs — MD.4).
//!
//! Every ```toml fenced block in `docs/config-reference.md` is a configuration
//! example shown to users. This test proves each one actually parses **and**
//! passes semantic validation via the real loader (`Config::load`) — so a
//! documented config example can never drift into something sipnab would
//! reject. (Spec §17: every documented example is executed and proven.)
#![cfg(feature = "native")]

use std::io::Write;

const CONFIG_REFERENCE: &str = include_str!("../docs/config-reference.md");

/// Extract the bodies of all ```toml fenced code blocks from markdown.
fn toml_blocks(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current = String::new();
    for line in md.lines() {
        let trimmed = line.trim_start();
        if !in_block && (trimmed == "```toml" || trimmed == "```TOML") {
            in_block = true;
            current.clear();
        } else if in_block && trimmed.starts_with("```") {
            in_block = false;
            blocks.push(std::mem::take(&mut current));
        } else if in_block {
            current.push_str(line);
            current.push('\n');
        }
    }
    blocks
}

#[test]
fn documented_config_samples_parse_and_validate() {
    let blocks = toml_blocks(CONFIG_REFERENCE);
    assert!(
        blocks.len() >= 5,
        "expected several documented config samples, found {}",
        blocks.len()
    );

    for (i, body) in blocks.iter().enumerate() {
        // Load through the real loader (parse + validate), exactly as sipnab
        // would at startup, by writing the sample to a temp file.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.toml");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        drop(f);

        let path_str = path.to_str().unwrap();
        let loaded = sipnab::config::Config::load(Some(path_str), false).unwrap_or_else(|e| {
            panic!("config sample #{i} failed to load (parse/validate):\n{body}\nerror: {e}");
        });
        // The limits section carries its own semantic validation.
        loaded.config.limits.validate().unwrap_or_else(|e| {
            panic!("config sample #{i} limits failed validation:\n{body}\nerror: {e}");
        });
    }
}
