// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every TFPS answer the references show has the keys sipnab sends.
//!
//! sipnab moved every TFPS surface to the vocabulary of TFPS's JSON mode
//! (`reason`, `disposition`, epoch seconds, `local`/`declared` refusals) while
//! `docs/rest-api.md` and `docs/mcp-tools.md` kept showing the draft it
//! replaced: `rule`, `verdict: "blocked"`, RFC 3339 timestamps, a six-field
//! status and `self`/`ignoreip` refusals. The route headings were gated
//! against the router and the tool sections against the tool list; the
//! examples inside them were compared with nothing, so a reader copying a
//! field name from the reference got one sipnab never sends.
//!
//! The expected keys are not written here. They come from serializing sipnab's
//! own types, read from the pinned fixtures, so the gate moves when the types
//! do and cannot keep a second copy of the vocabulary that drifts.
#![cfg(feature = "native")]

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sipnab::security::tfps::{TfpsAction, TfpsBanned, TfpsDropped, TfpsLabel, TfpsStatus};

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The keys sipnab serializes for `T`, from the first line of a fixture.
fn keys_of<T: DeserializeOwned + Serialize>(fixture: &str) -> BTreeSet<String> {
    let line = repo_file(&format!("tests/fixtures/{fixture}"));
    let line = line.lines().next().expect("fixture has a line");
    let value: T = serde_json::from_str(line).unwrap_or_else(|e| panic!("{fixture}: {e}"));
    match serde_json::to_value(value).expect("serializes") {
        Value::Object(m) => m.keys().cloned().collect(),
        other => panic!("{fixture} is not an object: {other}"),
    }
}

/// The JSON type of a value, as a word.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// For each key, the JSON types it takes across EVERY line of a fixture.
/// `null` is always allowed on top, because an example may show a field
/// that happens to be unknown.
fn kinds_of(fixture: &str) -> std::collections::BTreeMap<String, BTreeSet<&'static str>> {
    let mut out: std::collections::BTreeMap<String, BTreeSet<&'static str>> = Default::default();
    for line in repo_file(&format!("tests/fixtures/{fixture}")).lines() {
        let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        for (k, v) in m {
            let e = out.entry(k).or_default();
            e.insert(kind(&v));
            e.insert("null");
        }
    }
    out
}

/// The words TFPS answers a refused ban or unban with: `local`, `declared`
/// and `kernel` for `ban`, `not-blocked` for `unban`. Read from
/// `crates/tfps/src/bin/tfps_ctl.rs` at sippulse/tfps `984577dc`.
const REFUSALS: &[&str] = &["local", "declared", "kernel", "not-blocked"];

/// Values in `obj` whose JSON type the fixtures never give that key.
fn wrong_kinds(
    line: usize,
    what: &str,
    obj: &Value,
    kinds: &std::collections::BTreeMap<String, BTreeSet<&'static str>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in obj.as_object().into_iter().flatten() {
        if let Some(allowed) = kinds.get(k)
            && !allowed.contains(kind(v))
        {
            out.push(format!(
                "{line}: {what}.{k} is a {}, sipnab sends {allowed:?}",
                kind(v)
            ));
        }
    }
    out
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

/// Every fenced `json`/`jsonc` block in a page, `//` comment lines removed,
/// with the line it starts on. A block that is not JSON is skipped here and
/// left to the gates that own it.
fn json_blocks(page: &str) -> Vec<(usize, Value)> {
    let mut out = Vec::new();
    let mut body: Option<(usize, String)> = None;
    for (n, line) in page.lines().enumerate() {
        let t = line.trim_start();
        match &mut body {
            None if t == "```json" || t == "```jsonc" => body = Some((n + 1, String::new())),
            Some((start, text)) if t == "```" => {
                if let Ok(v) = serde_json::from_str::<Value>(text) {
                    out.push((*start, v));
                }
                body = None;
            }
            Some((_, text)) if !t.starts_with("//") => {
                text.push_str(line);
                text.push('\n');
            }
            Some(_) | None => {}
        }
    }
    out
}

/// What is wrong with one documented TFPS answer, as `(line, problem)`.
fn problems_in(page: &str) -> (usize, Vec<String>) {
    let status = keys_of::<TfpsStatus>("tfps-status-golden.json");
    let rows = [
        ("banned", keys_of::<TfpsBanned>("tfps-banned-golden.jsonl")),
        ("labels", keys_of::<TfpsLabel>("tfps-labels-golden.jsonl")),
        (
            "dropped",
            keys_of::<TfpsDropped>("tfps-dropped-golden.jsonl"),
        ),
    ];
    let action = keys_of::<TfpsAction>("tfps-ban-golden.jsonl");
    let mut checked = 0;
    let mut problems = Vec::new();
    for (line, v) in json_blocks(page) {
        // A TFPS answer, and only a TFPS answer, leads with `installed`.
        if v.get("installed").is_none() {
            continue;
        }
        checked += 1;
        let top = keys(&v);
        let expect_top = if v["installed"] == Value::Bool(false) {
            set(&["installed", "reason"])
        } else if v.get("status").is_some() {
            set(&["installed", "tfps_ctl", "status"])
        } else if v.get("rows").is_some() {
            set(&[
                "installed",
                "tfps_ctl",
                "rows",
                "total",
                "returned",
                "truncated",
            ])
        } else {
            set(&["installed", "tfps_ctl", "action"])
        };
        if top != expect_top {
            problems.push(format!(
                "{line}: answer keys {top:?}, sipnab sends {expect_top:?}"
            ));
        }
        if let Some(s) = v.get("status")
            && keys(s) != status
        {
            problems.push(format!(
                "{line}: status keys {:?}, sipnab sends {status:?}",
                keys(s)
            ));
        }
        for row in v
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let k = keys(row);
            if !rows.iter().any(|(_, r)| *r == k) {
                problems.push(format!(
                    "{line}: row keys {k:?} match no row sipnab sends ({})",
                    rows.iter()
                        .map(|(n, r)| format!("{n}: {r:?}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
        if let Some(s) = v.get("status") {
            problems.extend(wrong_kinds(
                line,
                "status",
                s,
                &kinds_of("tfps-status-golden.json"),
            ));
        }
        for row in v
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let k = keys(row);
            for (name, fixture) in [
                ("banned", "tfps-banned-golden.jsonl"),
                ("labels", "tfps-labels-golden.jsonl"),
                ("dropped", "tfps-dropped-golden.jsonl"),
            ] {
                let kinds = kinds_of(fixture);
                if kinds.keys().cloned().collect::<BTreeSet<_>>() == k {
                    problems.extend(wrong_kinds(line, name, row, &kinds));
                }
            }
        }
        if let Some(a) = v.get("action") {
            let mut kinds = kinds_of("tfps-ban-golden.jsonl");
            for (k, v) in kinds_of("tfps-unban-golden.jsonl") {
                kinds.entry(k).or_default().extend(v);
            }
            problems.extend(wrong_kinds(line, "action", a, &kinds));
            if let Some(r) = a.get("refused").and_then(Value::as_str)
                && !REFUSALS.contains(&r)
            {
                problems.push(format!(
                    "{line}: refused {r:?} is not a word TFPS answers with {REFUSALS:?}"
                ));
            }
        }
        if let Some(a) = v.get("action")
            && keys(a) != action
        {
            problems.push(format!(
                "{line}: action keys {:?}, sipnab sends {action:?}",
                keys(a)
            ));
        }
    }
    (checked, problems)
}

fn assert_page(rel: &str, at_least: usize) {
    let (checked, problems) = problems_in(&repo_file(rel));
    assert!(
        checked >= at_least,
        "{rel}: found {checked} TFPS answers, expected at least {at_least}; the \
         block reader has stopped matching and this gate proves nothing"
    );
    assert!(
        problems.is_empty(),
        "{rel} shows TFPS answers sipnab does not send:\n{}",
        problems.join("\n")
    );
}

#[test]
fn the_rest_reference_shows_the_tfps_answers_sipnab_sends() {
    assert_page("docs/rest-api.md", 7);
}

#[test]
fn the_mcp_reference_shows_the_tfps_answers_sipnab_sends() {
    assert_page("docs/mcp-tools.md", 7);
}
