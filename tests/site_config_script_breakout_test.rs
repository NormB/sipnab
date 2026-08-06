// SPDX-License-Identifier: MIT OR Apache-2.0

//! No string in `website/config.toml` may carry `</`, the byte pair that ends
//! a `<script>` element.
//!
//! `base.html` renders four config values inside
//! `<script type="application/ld+json">` as `{{ x | json_encode | safe }}`,
//! and Tera's `json_encode` does NOT escape the forward slash — a value
//! containing `</script>` closes the element early and hands the rest of the
//! page to the HTML parser as markup. The values are static today, so the
//! property must be enforced, not assumed.
//!
//! `site_journey_test.rs` already holds the template side of this: which keys
//! feed the block, and that every `| safe` bypass is on a reviewed allowlist.
//! This file holds the value side, and it parses the config with a real TOML
//! parser instead of a line regex because the regex form was shown to pass a
//! payload the parser sees: TOML admits the same string as `"..."`, `'...'`,
//! `"""..."""` or `'''...'''`, and a check keyed to the double-quoted shape
//! silently skips the other three. What Zola interpolates is the PARSED
//! value, so that is the thing checked.
//!
//! Every string in the file is swept, not just the four the block uses now:
//! any config value is one `{{ config.x | json_encode | safe }}` away from a
//! script element, none of them legitimately needs `</`, and a sweep cannot
//! be bypassed by wiring a fifth value into the template.

use std::path::Path;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every string value in a parsed TOML document, as `(dotted.path, value)`.
fn string_values(prefix: &str, value: &toml::Value, out: &mut Vec<(String, String)>) {
    match value {
        toml::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        toml::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                string_values(&format!("{prefix}[{i}]"), item, out);
            }
        }
        toml::Value::Table(table) => {
            for (key, item) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                string_values(&path, item, out);
            }
        }
        _ => {}
    }
}

/// The `(path, value)` pairs in a TOML document whose value could close a
/// `<script>` element. This is the whole gate; both tests below drive it so
/// the assertion on the shipped config and the proof of the mechanism can
/// never drift apart.
fn script_closing_values(doc: &str) -> Vec<(String, String)> {
    let parsed: toml::Value = toml::from_str(doc).expect("config must stay parseable TOML");
    let mut strings = Vec::new();
    string_values("", &parsed, &mut strings);
    assert!(
        !strings.is_empty(),
        "the TOML document parsed to no string values at all — the sweep read \
         nothing and this gate would pass vacuously"
    );
    strings
        .into_iter()
        .filter(|(_, v)| v.contains("</"))
        .collect()
}

/// The config keys `base.html` interpolates into the JSON-LD block today.
/// Renaming one fails here so the gate is re-pointed consciously instead of
/// silently covering nothing.
const JSON_LD_KEYS: [&str; 4] = [
    "title",
    "description",
    "base_url",
    "extra.published_version",
];

/// No string value in the shipped `website/config.toml` can close the
/// `<script>` element that holds the JSON-LD block.
#[test]
fn no_site_config_string_survives_parsing_with_a_script_closer_in_it() {
    let cfg = std::fs::read_to_string(repo().join("website/config.toml"))
        .expect("read website/config.toml");

    let violations = script_closing_values(&cfg);
    assert!(
        violations.is_empty(),
        "these website/config.toml values contain `</`, which Tera's \
         json_encode does NOT escape — rendered into the JSON-LD block they \
         would terminate its <script> element and the rest of the page would \
         be parsed as markup: {violations:?}"
    );

    // The four values the block renders must actually be present under the
    // names the template uses, or the sweep above proved nothing about them.
    let parsed: toml::Value = toml::from_str(&cfg).expect("parse website/config.toml");
    let mut strings = Vec::new();
    string_values("", &parsed, &mut strings);
    for key in JSON_LD_KEYS {
        let value = strings
            .iter()
            .find(|(path, _)| path == key)
            .unwrap_or_else(|| {
                panic!(
                    "website/config.toml no longer has a string at `{key}`, \
                     which base.html interpolates into the JSON-LD block — \
                     update JSON_LD_KEYS to follow the template"
                )
            });
        // Stricter than `</` for the values that provably feed the block:
        // nothing there needs an angle bracket, and allowing one is what
        // makes the `</script>` case reachable at all.
        assert!(
            !value.1.contains('<') && !value.1.contains('>'),
            "config value `{key}` contains an angle bracket and is rendered \
             inside the JSON-LD <script> element: {:?}",
            value.1
        );
    }
    assert!(
        strings.len() >= 15,
        "only {} string values were found in website/config.toml — the sweep \
         stopped reading the real file and this gate checked almost nothing",
        strings.len()
    );
}

/// The gate rejects a `</script>` payload in every TOML quoting form, and
/// accepts a clean document.
///
/// This is the mutation test made permanent: the line-regex predecessor of
/// this gate passed the literal-quoted form of exactly this payload, so the
/// mechanism — not just the current values — is what must stay proven.
#[test]
fn the_gate_rejects_a_script_closer_in_every_toml_quoting_form() {
    let injected: [(&str, String); 4] = [
        (
            "basic string",
            "title = \"sipnab</script><script>alert(1)\"\n".to_string(),
        ),
        (
            "literal string",
            "title = 'sipnab</script><script>alert(1)'\n".to_string(),
        ),
        (
            "multi-line basic string",
            "title = \"\"\"sipnab</script><script>alert(1)\"\"\"\n".to_string(),
        ),
        (
            "multi-line literal string",
            "title = '''sipnab</script><script>alert(1)'''\n".to_string(),
        ),
    ];
    for (form, doc) in &injected {
        let violations = script_closing_values(doc);
        assert_eq!(
            violations.len(),
            1,
            "a `</script>` payload written as a TOML {form} was not flagged — \
             the gate no longer catches the breakout it exists for"
        );
        assert_eq!(
            violations[0].0, "title",
            "the violation must name the key ({form})"
        );
    }

    // And the gate must not cry wolf: a document shaped like the real config,
    // with a `/` that is NOT part of `</`, carries no violations.
    let clean = r#"
title = "sipnab"
description = "SIP & RTP analysis. One binary."
base_url = "https://www.sipnab.com"

[extra]
published_version = "0.5.82"
"#;
    let violations = script_closing_values(clean);
    assert!(
        violations.is_empty(),
        "a clean config was flagged: {violations:?} — a gate that fails on \
         good input gets deleted, not fixed"
    );
}
