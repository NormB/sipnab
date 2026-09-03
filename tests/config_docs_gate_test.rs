// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every `[security]` config key the program reads is documented.
//!
//! # The defect this exists for
//!
//! `fraud_destination` was added to `SecurityConfig`, wired, tested, and named
//! in the flag's reference row -- and never given a row in
//! `docs/config-reference.md`, where an operator writing a config file looks.
//! No gate noticed: the docs-drift tests pair flags with their rows, not config
//! keys. A key an operator cannot find is a key they cannot use.

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The `pub` field names of `struct NAME { ... }` in Rust source.
fn pub_fields(src: &str, name: &str) -> Vec<String> {
    let start = src
        .find(&format!("pub struct {name} {{"))
        .unwrap_or_else(|| panic!("no `pub struct {name}`"));
    let body = &src[start..];
    let end = body.find("\n}").expect("struct closes");
    body[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("pub ")?;
            let (field, _) = rest.split_once(':')?;
            Some(field.trim().to_string())
        })
        .collect()
}

/// Fields with no `` `field` `` mention in `doc`.
fn undocumented(fields: &[String], doc: &str) -> Vec<String> {
    fields
        .iter()
        .filter(|f| !doc.contains(&format!("`{f}`")))
        .cloned()
        .collect()
}

#[test]
fn every_security_config_key_has_a_row_in_the_config_reference() {
    let fields = pub_fields(&read("src/config.rs"), "SecurityConfig");
    assert!(fields.len() > 10, "parsed only {} fields", fields.len());
    let missing = undocumented(&fields, &read("docs/config-reference.md"));
    assert!(
        missing.is_empty(),
        "[security] keys the program reads but docs/config-reference.md never names: {missing:?}"
    );
}

/// POSITIVE CONTROL: a key absent from the doc is reported, a present one is not.
#[test]
fn the_checker_reports_exactly_the_missing_keys() {
    // `gamma` is private: not a config key, so it must not be demanded of the docs.
    let src = "pub struct S {\n    /// a\n    pub alpha: Option<u8>,\n    pub beta: bool,\n    gamma: u8,\n}\n";
    let fields = pub_fields(src, "S");
    assert_eq!(
        fields,
        ["alpha", "beta"],
        "private fields are not config keys"
    );
    assert_eq!(undocumented(&fields, "| `alpha` | ... |"), ["beta"]);
    assert!(undocumented(&fields, "`alpha` and `beta`").is_empty());
}

/// The field parser stops at the struct's own closing brace, not a later one.
#[test]
fn the_field_parser_does_not_run_into_the_next_struct() {
    let src = "pub struct A {\n    pub one: u8,\n}\n\npub struct B {\n    pub two: u8,\n}\n";
    assert_eq!(pub_fields(src, "A"), ["one"]);
    assert_eq!(pub_fields(src, "B"), ["two"]);
}
