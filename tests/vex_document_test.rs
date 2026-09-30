// SPDX-License-Identifier: MIT OR Apache-2.0
//! The OpenVEX document states, in machine-readable form, every advisory the
//! project has accepted as not affecting it.
//!
//! OpenSSF Baseline VM-04.02 asks for vulnerabilities that do not affect the
//! project to be published in VEX form. The accepted exceptions already live in
//! two scanner configs, `deny.toml` (`[advisories] ignore`) and
//! `osv-scanner.toml` (`[[IgnoredVulns]]`), each with its reason. This file
//! holds `vex/sipnab.openvex.json` to exactly that set: an exception without a
//! VEX statement is an undisclosed one, and a statement without an exception is
//! a stale claim.

use std::collections::BTreeSet;
use std::path::Path;

const VEX: &str = "vex/sipnab.openvex.json";

/// The OpenVEX v0.2.0 justifications for `not_affected`.
const JUSTIFICATIONS: &[&str] = &[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Advisory IDs quoted anywhere in `text` (RUSTSEC, GHSA or CVE form).
fn advisory_ids(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("");
        for token in code.split(|c: char| c == '"' || c.is_whitespace() || c == ',') {
            if token.starts_with("RUSTSEC-")
                || token.starts_with("GHSA-")
                || token.starts_with("CVE-")
            {
                out.insert(token.to_string());
            }
        }
    }
    out
}

/// The IDs the scanners are told to accept: `deny.toml`'s `[advisories]
/// ignore` list and `osv-scanner.toml`'s `id =` lines.
fn accepted() -> BTreeSet<String> {
    let deny = read("deny.toml");
    let start = deny
        .find("[advisories]")
        .expect("deny.toml has [advisories]");
    let section = &deny[start..];
    let list_start = section
        .find("ignore = [")
        .expect("[advisories] has an ignore list");
    let list_end = section[list_start..].find(']').expect("ignore list closes") + list_start;
    let mut ids = advisory_ids(&section[list_start..list_end]);
    for line in read("osv-scanner.toml").lines() {
        if let Some(rest) = line.trim().strip_prefix("id = ") {
            ids.insert(rest.trim_matches('"').to_string());
        }
    }
    ids
}

fn document() -> serde_json::Value {
    serde_json::from_str(&read(VEX)).unwrap_or_else(|e| panic!("{VEX} is not JSON: {e}"))
}

#[test]
fn the_vex_document_is_openvex() {
    let doc = document();
    let context = doc["@context"].as_str().unwrap_or_default();
    assert!(
        context.starts_with("https://openvex.dev/ns"),
        "{VEX} @context is {context:?}, not an OpenVEX namespace"
    );
    for key in ["@id", "author", "timestamp", "version"] {
        assert!(!doc[key].is_null(), "{VEX} lacks the required `{key}`");
    }
}

#[test]
fn every_accepted_advisory_has_a_not_affected_statement_and_no_other() {
    let doc = document();
    let statements = doc["statements"]
        .as_array()
        .expect("statements is an array");
    let mut stated = BTreeSet::new();
    for s in statements {
        let name = s["vulnerability"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            s["status"].as_str(),
            Some("not_affected"),
            "{name}: an accepted exception is stated as not_affected"
        );
        let why = s["justification"].as_str().unwrap_or_default();
        assert!(
            JUSTIFICATIONS.contains(&why),
            "{name}: justification {why:?} is not an OpenVEX one"
        );
        assert!(
            s["impact_statement"].as_str().is_some_and(|t| t.len() > 40),
            "{name}: say why in `impact_statement`, as the scanner configs do"
        );
        assert!(
            s["products"].as_array().is_some_and(|p| !p.is_empty()),
            "{name}: names no product"
        );
        stated.insert(name);
    }
    let accepted = accepted();
    assert!(
        !accepted.is_empty(),
        "found no accepted advisories; the reader broke"
    );
    assert_eq!(
        stated, accepted,
        "{VEX} must state exactly the advisories deny.toml and osv-scanner.toml accept"
    );
}

#[test]
fn security_md_links_the_vex_document() {
    assert!(
        read("SECURITY.md").contains(VEX),
        "SECURITY.md must link {VEX} so a reader finds the accepted advisories"
    );
}
