// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate a vCon container against the schema sipnab vendors.
//!
//! # Why this exists
//!
//! A validation pass over 4,216 real containers found 2 that the working
//! group's own schema rejects. Nothing on any sipnab surface let the producer
//! notice before a conserver did, and a store that refuses a container reports
//! its refusal to whoever posted it — not to whoever built it.
//!
//! # Why not a JSON Schema engine
//!
//! Because there is not one here to use. `jsonschema` is a DEV-dependency: the
//! gates in `tests/` compile against it and the shipped binary does not, so a
//! validator built on it would exist only in the test tree — which is exactly
//! where the problem already was.
//!
//! So this is a draft-07 SUBSET, driven by the vendored file rather than by a
//! transcription of it. The schema is the source; nothing here restates a
//! constraint it states.
//!
//! # The subset is enforced, not assumed
//!
//! A validator that ignores the keyword it does not know is a validator that
//! passes everything once somebody re-vendors a richer schema. So the keyword
//! set is CHECKED: [`unimplemented_keywords`] walks the vendored file, and a
//! keyword outside the implemented set makes every validation report
//! [`SchemaVerdict::Invalid`] naming it. A re-vendor that outgrows this fails
//! loudly instead of quietly certifying whatever it is handed.
//!
//! # No documented deviation
//!
//! The vendored file is the working group's
//! [draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B) schema, byte for byte. The
//! core-03 copy removed `type` from the Dialog Object's `required` list so that
//! a Dialog Object "with no parameters", which core-03's prose allowed and its
//! schema rejected, could pass as a named deviation. core-04 replaced that
//! object by a placeholder that names its type
//! ([core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3)), so the deviation and the verdict
//! that excused it are gone: a container is valid or it is not.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Serialize;
use serde_json::Value;

/// The vendored schema, compiled in.
///
/// The same bytes the gates in `tests/` validate against, so the answer this
/// gives and the answer the build gives cannot come from two files.
const SCHEMA_TEXT: &str = include_str!("../../tests/schemas/vcon.schema.json");

/// Where the schema lives, for a report a reader can act on.
pub const SCHEMA_PATH: &str = "tests/schemas/vcon.schema.json";

/// Keywords this validator implements.
const IMPLEMENTED: &[&str] = &[
    "$ref",
    "allOf",
    "anyOf",
    "const",
    "dependencies",
    "else",
    "enum",
    "format",
    "if",
    "items",
    "minimum",
    "not",
    "oneOf",
    "properties",
    "required",
    "then",
    "type",
];

/// Keywords that annotate and constrain nothing, so ignoring them is correct
/// rather than a gap.
const ANNOTATIONS: &[&str] = &[
    "$comment",
    "$id",
    "$schema",
    "definitions",
    "description",
    "title",
];

/// How a container stands against the vendored schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum SchemaVerdict {
    /// Nothing to report.
    Valid,
    /// At least one finding.
    Invalid,
}

impl SchemaVerdict {
    /// The token this verdict serializes as.
    ///
    /// Spelled once so a test, a doc page and the wire cannot disagree.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

/// One place the container disagrees with the schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SchemaFinding {
    /// JSON Pointer to the offending value, `/dialog/2` shaped.
    pub instance_path: String,
    /// The schema keyword that refused it.
    pub keyword: &'static str,
    /// What was wrong, in one sentence.
    pub detail: String,
}

/// What a validation pass found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SchemaReport {
    /// The one-word answer.
    pub verdict: SchemaVerdict,
    /// The `$id` the vendored schema declares.
    pub schema_id: String,
    /// Where that schema lives in this repository.
    pub schema_path: &'static str,
    /// Every finding. Empty on a clean pass.
    pub errors: Vec<SchemaFinding>,
}

/// The vendored schema, parsed once.
fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(SCHEMA_TEXT).unwrap_or_else(|e| {
            // A compiled-in constant that will not parse is a build that
            // shipped a broken file, and every validation below would be
            // meaningless. Fail where the fact is, not in a caller that
            // cannot act on it.
            // gate: panic because SCHEMA_TEXT is a compile-time constant, not
            // input, and every test that validates a vCon parses it first.
            panic!("the vendored vCon schema is not valid JSON: {e}")
        })
    })
}

/// Keywords the vendored schema uses that this validator does not implement.
///
/// The tripwire on the subset. A re-vendor that introduces `additionalProperties`,
/// `patternProperties`, a tuple-form `items` or anything else in the draft-07
/// vocabulary this file does not implement shows up here, and [`validate`] refuses rather than
/// quietly ignoring the new constraint.
///
/// # Returns
///
/// The offending keyword names, sorted, or an empty set.
#[must_use]
pub fn unimplemented_keywords() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk_keywords(schema(), &mut out);
    out
}

/// Collect the keywords a schema node and its subschemas use.
fn walk_keywords(node: &Value, out: &mut BTreeSet<String>) {
    let Some(map) = node.as_object() else {
        return;
    };
    for (key, value) in map {
        if ANNOTATIONS.contains(&key.as_str()) {
            // `definitions` holds subschemas even though it constrains
            // nothing itself, so its members are still walked.
            if key == "definitions"
                && let Some(defs) = value.as_object()
            {
                for sub in defs.values() {
                    walk_keywords(sub, out);
                }
            }
            continue;
        }
        if !IMPLEMENTED.contains(&key.as_str()) {
            out.insert(key.clone());
            continue;
        }
        match key.as_str() {
            "properties" => {
                if let Some(props) = value.as_object() {
                    for sub in props.values() {
                        walk_keywords(sub, out);
                    }
                }
            }
            "items" => match value {
                Value::Object(_) => walk_keywords(value, out),
                // Tuple validation. Not implemented, and it changes what
                // `items` MEANS, so it is named rather than walked.
                _ => {
                    out.insert("items (tuple form)".to_owned());
                }
            },
            "allOf" | "anyOf" | "oneOf" => {
                if let Some(branches) = value.as_array() {
                    for sub in branches {
                        walk_keywords(sub, out);
                    }
                }
            }
            "if" | "then" | "else" | "not" => walk_keywords(value, out),
            "dependencies" => {
                if let Some(deps) = value.as_object() {
                    for sub in deps.values() {
                        // Schema dependencies are a different feature from
                        // property dependencies and only the second is
                        // implemented.
                        if !sub.is_array() {
                            out.insert("dependencies (schema form)".to_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Validate a container against the vendored schema.
///
/// # Arguments
///
/// * `container` — the container, as JSON. Anything at all: a document sipnab
///   just built, or one a caller was handed by somebody else.
///
/// # Returns
///
/// A [`SchemaReport`]: the verdict and every finding.
#[must_use]
pub fn validate(container: &Value) -> SchemaReport {
    let schema_id = schema()["$id"].as_str().unwrap_or_default().to_owned();

    let unimplemented = unimplemented_keywords();
    if !unimplemented.is_empty() {
        return outgrown(&unimplemented, schema_id);
    }

    let mut errors = Vec::new();
    check(schema(), container, "", &mut errors);

    let verdict = if errors.is_empty() {
        SchemaVerdict::Valid
    } else {
        SchemaVerdict::Invalid
    };

    SchemaReport {
        verdict,
        schema_id,
        schema_path: SCHEMA_PATH,
        errors,
    }
}

/// The report a schema this validator has outgrown produces.
///
/// The one case where the answer is about the VALIDATOR rather than about the
/// container. It is a FAILURE rather than a clean pass, because a pass here
/// would be this code certifying constraints it never read — which is the
/// shape of every instrument that fails silently and looks like one that
/// passed.
///
/// A whole function rather than a branch inside [`validate`] so a test can
/// reach it without re-vendoring the schema. A guard whose effect nothing can
/// exercise is a guard nobody knows works.
fn outgrown(unimplemented: &BTreeSet<String>, schema_id: String) -> SchemaReport {
    SchemaReport {
        verdict: SchemaVerdict::Invalid,
        schema_id,
        schema_path: SCHEMA_PATH,
        errors: vec![SchemaFinding {
            instance_path: String::new(),
            keyword: "$schema",
            detail: format!(
                "the vendored schema uses keyword(s) this validator does not implement: {}. \
                 Nothing was checked. Implement them in src/output/vcon_schema.rs, or revert \
                 the re-vendor",
                unimplemented
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }],
    }
}

/// Validate one instance against one schema node.
fn check(node: &Value, instance: &Value, path: &str, out: &mut Vec<SchemaFinding>) {
    let Some(map) = node.as_object() else {
        return;
    };

    // draft-07: a `$ref` replaces its siblings rather than joining them.
    if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
        match resolve(reference) {
            Some(target) => check(target, instance, path, out),
            None => out.push(SchemaFinding {
                instance_path: path.to_owned(),
                keyword: "$ref",
                detail: format!("the schema references `{reference}`, which it does not define"),
            }),
        }
        return;
    }

    if let Some(expected) = map.get("type")
        && !type_matches(expected, instance)
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "type",
            detail: format!("expected type {expected}, found {}", type_name(instance)),
        });
        // Every keyword below reads the instance as a type it is not, so
        // reporting them too would bury the one finding that matters.
        return;
    }

    if let Some(allowed) = map.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "enum",
            detail: format!(
                "`{instance}` is not one of {}",
                Value::Array(allowed.clone())
            ),
        });
    }

    if let Some(expected) = map.get("const")
        && expected != instance
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "const",
            detail: format!("expected `{expected}`, found `{instance}`"),
        });
    }

    if let Some(minimum) = map.get("minimum").and_then(Value::as_f64)
        && let Some(actual) = instance.as_f64()
        && actual < minimum
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "minimum",
            detail: format!("{actual} is below the minimum {minimum}"),
        });
    }

    if let Some(format) = map.get("format").and_then(Value::as_str)
        && let Some(text) = instance.as_str()
        && !format_matches(format, text)
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "format",
            detail: format!("`{text}` is not a valid {format}"),
        });
    }

    if let Some(branches) = map.get("anyOf").and_then(Value::as_array)
        && !branches.iter().any(|b| passes(b, instance))
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "anyOf",
            detail: format!("matches none of the {} permitted shapes", branches.len()),
        });
    }

    if let Some(branches) = map.get("oneOf").and_then(Value::as_array) {
        let matched = branches.iter().filter(|b| passes(b, instance)).count();
        if matched != 1 {
            out.push(SchemaFinding {
                instance_path: path.to_owned(),
                keyword: "oneOf",
                detail: format!(
                    "matches {matched} of the {} permitted shapes; exactly one must match",
                    branches.len()
                ),
            });
        }
    }

    check_conditionals(map, instance, path, out);

    if let Some(object) = instance.as_object() {
        if let Some(required) = map.get("required").and_then(Value::as_array) {
            let missing: Vec<String> = required
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| !object.contains_key(*name))
                .map(str::to_owned)
                .collect();
            if !missing.is_empty() {
                out.push(SchemaFinding {
                    instance_path: path.to_owned(),
                    keyword: "required",
                    detail: format!("missing required properties: {}", missing.join(", ")),
                });
            }
        }

        if let Some(properties) = map.get("properties").and_then(Value::as_object) {
            for (name, subschema) in properties {
                if let Some(value) = object.get(name) {
                    check(subschema, value, &format!("{path}/{name}"), out);
                }
            }
        }

        if let Some(dependencies) = map.get("dependencies").and_then(Value::as_object) {
            for (name, required) in dependencies {
                if !object.contains_key(name) {
                    continue;
                }
                let Some(names) = required.as_array() else {
                    continue;
                };
                let missing: Vec<String> = names
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|n| !object.contains_key(*n))
                    .map(str::to_owned)
                    .collect();
                if !missing.is_empty() {
                    out.push(SchemaFinding {
                        instance_path: path.to_owned(),
                        keyword: "dependencies",
                        detail: format!(
                            "`{name}` is present, which requires: {}",
                            missing.join(", ")
                        ),
                    });
                }
            }
        }
    }

    if let Some(items) = map.get("items")
        && let Some(array) = instance.as_array()
    {
        for (index, value) in array.iter().enumerate() {
            check(items, value, &format!("{path}/{index}"), out);
        }
    }
}

/// The draft-07 combinators the core-04 schema introduced: `allOf`, `if` with
/// `then` and `else`, and `not`.
fn check_conditionals(
    map: &serde_json::Map<String, Value>,
    instance: &Value,
    path: &str,
    out: &mut Vec<SchemaFinding>,
) {
    // Each `allOf` branch is a constraint of its own, so its findings are
    // reported as they are rather than folded into one "allOf failed": a
    // producer told "`disposition` is missing" can fix it, and one told
    // "branch 0 of 9 failed" cannot.
    if let Some(branches) = map.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            check(branch, instance, path, out);
        }
    }

    // draft-07 `if`: the condition only selects which of `then` and `else`
    // applies, and is never itself a finding.
    if let Some(condition) = map.get("if") {
        let branch = if passes(condition, instance) {
            map.get("then")
        } else {
            map.get("else")
        };
        if let Some(branch) = branch {
            check(branch, instance, path, out);
        }
    }

    if let Some(forbidden) = map.get("not")
        && passes(forbidden, instance)
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "not",
            detail: forbidden_detail(forbidden, instance),
        });
    }
}

/// What a `not` refused, in terms a producer can act on.
///
/// The core-04 schema uses `not` for one shape only: a set of properties that
/// must not be present together, or must not be present on this Dialog Object
/// type, written as `required` lists. So the detail names the properties the
/// instance carries from those lists. Any other `not` gets a generic sentence
/// rather than an invented explanation.
fn forbidden_detail(forbidden: &Value, instance: &Value) -> String {
    let mut lists: Vec<&Value> = vec![forbidden];
    if let Some(branches) = forbidden.get("anyOf").and_then(Value::as_array) {
        lists.extend(branches.iter().filter(|b| passes(b, instance)));
    }
    let present: Vec<String> = lists
        .iter()
        .filter_map(|node| node.get("required").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| instance.get(*name).is_some())
        .map(|name| format!("`{name}`"))
        .collect();
    if present.is_empty() {
        "matches a shape the schema forbids here".to_owned()
    } else {
        format!(
            "carries {}, which the schema forbids here",
            present.join(" and ")
        )
    }
}

/// Does this instance satisfy this subschema, ignoring where it failed?
///
/// The branch test `anyOf`, `oneOf`, `if` and `not` need. It runs the same [`check`], so a
/// branch and a top-level constraint can never be judged by two rules.
fn passes(node: &Value, instance: &Value) -> bool {
    let mut findings = Vec::new();
    check(node, instance, "", &mut findings);
    findings.is_empty()
}

/// Resolve a local `#/definitions/NAME` reference.
///
/// Local only, and that is a property of the vendored file rather than a
/// shortcut: an external `$ref` would be a fetch, and a validator that reaches
/// the network to decide whether a container is well formed is a validator no
/// air-gapped capture host can run. A reference this cannot resolve is
/// reported, never assumed to pass.
fn resolve(reference: &str) -> Option<&'static Value> {
    let name = reference.strip_prefix("#/definitions/")?;
    schema().get("definitions")?.get(name)
}

/// The JSON type name of a value, in the schema's vocabulary.
fn type_name(instance: &Value) -> &'static str {
    match instance {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Does the instance match a `type` keyword, which may name one type or many?
fn type_matches(expected: &Value, instance: &Value) -> bool {
    match expected {
        Value::String(name) => one_type_matches(name, instance),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|name| one_type_matches(name, instance)),
        _ => false,
    }
}

/// Does the instance match one named type?
fn one_type_matches(name: &str, instance: &Value) -> bool {
    match name {
        // A float with a zero fraction IS an integer in JSON Schema, which is
        // not what `serde_json` means by `is_i64`. `1.0` reaching a field
        // typed `integer` has to pass, or a producer that serialized a whole
        // number as a float gets an error naming the wrong problem.
        "integer" => instance
            .as_f64()
            .is_some_and(|v| v.fract() == 0.0 && v.is_finite()),
        "number" => instance.is_number(),
        other => type_name(instance) == other,
    }
}

/// Does a string satisfy a `format` this validator enforces?
///
/// Three formats, because three is what the vendored schema uses. An unknown
/// format cannot reach here: [`unimplemented_keywords`] would have to let
/// `format` through, and it names every format the file carries.
fn format_matches(format: &str, text: &str) -> bool {
    match format {
        "date-time" => chrono::DateTime::parse_from_rfc3339(text).is_ok(),
        "uuid" => is_uuid(text),
        "uri" => is_uri(text),
        // Unreachable while the vendored schema uses only the three above, and
        // permissive rather than fatal if it ever is reached: an unknown
        // format is an ANNOTATION in draft-07, and inventing a rule for it
        // would refuse a container the schema accepts.
        _ => true,
    }
}

/// `8-4-4-4-12` hex, the only spelling RFC 9562 defines.
fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(want, got)| got.len() == *want)
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A URI reference with a scheme, per [RFC 3986 section 3.1](https://www.rfc-editor.org/rfc/rfc3986#section-3.1).
fn is_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    !rest.is_empty()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        && !text.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// The smallest container the schema accepts.
    fn minimal() -> Value {
        json!({
            "vcon": "0.4.0",
            "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde",
            "created_at": "2026-09-01T12:00:00Z",
        })
    }

    /// A container with one Dialog Object of the given shape.
    fn with_dialog(object: Value) -> Value {
        let mut container = minimal();
        container["dialog"] = json!([object]);
        container
    }

    /// Every document the cross-check runs over: valid ones and the ways a
    /// container goes wrong, each exercising a keyword this validator claims.
    fn corpus() -> Vec<(&'static str, Value)> {
        vec![
            ("minimal", minimal()),
            (
                "missing uuid",
                json!({"created_at": "2026-09-01T12:00:00Z"}),
            ),
            (
                "missing created_at",
                json!({"uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde"}),
            ),
            ("wrong syntax version", {
                let mut c = minimal();
                c["vcon"] = json!("0.3.0");
                c
            }),
            ("subject is not a string", {
                let mut c = minimal();
                c["subject"] = json!(7);
                c
            }),
            ("extensions carries a number", {
                let mut c = minimal();
                c["extensions"] = json!(["sip", 3]);
                c
            }),
            (
                "dialog with a start",
                with_dialog(json!({"type": "recording", "start": "2026-09-01T12:00:00Z"})),
            ),
            (
                "dialog with no start",
                with_dialog(json!({"type": "transfer"})),
            ),
            ("empty dialog object", with_dialog(json!({}))),
            (
                "dialog type outside the enum",
                with_dialog(json!({"type": "signaling", "start": "2026-09-01T12:00:00Z"})),
            ),
            (
                "negative originator",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "originator": -1})),
            ),
            (
                "duration as a float",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "duration": 12.5})),
            ),
            (
                "duration as a string",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "duration": "12"})),
            ),
            (
                "parties as nested indices",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "parties": [[0, 1], 2]})),
            ),
            (
                "transfer_target as an array",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "transfer_target": [1, 2]})),
            ),
            (
                "transfer_target as a string",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "transfer_target": "1"})),
            ),
            (
                "content_hash as a list",
                with_dialog(json!({"start": "2026-09-01T12:00:00Z", "content_hash": ["a", "b"]})),
            ),
            (
                "start is not a timestamp",
                with_dialog(json!({"start": "yesterday"})),
            ),
            ("redacted url that is not a uri", {
                let mut c = minimal();
                c["redacted"] = json!({
                    "type": "pii",
                    "url": "not a uri",
                    "content_hash": "sha512-abc",
                });
                c
            }),
            (
                "party history without an event",
                with_dialog(json!({
                    "start": "2026-09-01T12:00:00Z",
                    "party_history": [{"party": 0, "time": "2026-09-01T12:00:00Z"}],
                })),
            ),
            (
                "party history with a good event",
                with_dialog(json!({
                    "start": "2026-09-01T12:00:00Z",
                    "party_history": [
                        {"party": 0, "time": "2026-09-01T12:00:00Z", "event": "join"}
                    ],
                })),
            ),
            (
                "party history with an unknown event",
                with_dialog(json!({
                    "start": "2026-09-01T12:00:00Z",
                    "party_history": [
                        {"party": 0, "time": "2026-09-01T12:00:00Z", "event": "transferred"}
                    ],
                })),
            ),
            ("redacted url without a content_hash", {
                let mut c = minimal();
                c["redacted"] = json!({"type": "pii", "url": "https://example.com/v"});
                c
            }),
            ("redacted url with a content_hash", {
                let mut c = minimal();
                c["redacted"] = json!({
                    "type": "pii",
                    "url": "https://example.com/v",
                    "content_hash": "sha512-abc",
                });
                c
            }),
            ("attachment missing its dialog index", {
                let mut c = minimal();
                c["attachments"] = json!([{"start": "2026-09-01T12:00:00Z", "party": 0}]);
                c
            }),
            ("analysis without a vendor", {
                let mut c = minimal();
                c["analysis"] = json!([{"type": "report"}]);
                c
            }),
            ("analysis with everything it needs", {
                let mut c = minimal();
                c["analysis"] = json!([{"type": "report", "vendor": "sipnab", "dialog": 0}]);
                c
            }),
            ("party with a civic address", {
                let mut c = minimal();
                c["parties"] = json!([{"name": "Alice", "civicaddress": {"country": "US"}}]);
                c
            }),
            ("party whose civic address is a string", {
                let mut c = minimal();
                c["parties"] = json!([{"name": "Alice", "civicaddress": "US"}]);
                c
            }),
            ("core-04 Appendix A.4 example", core_04_example_a4()),
            (
                "core-04 placeholder",
                with_dialog(json!({"type": "recording"})),
            ),
            (
                "recording carrying parties",
                with_dialog(json!({"type": "recording", "parties": [0, 1]})),
            ),
            (
                "keyup with a button",
                with_dialog(json!({
                    "type": "recording",
                    "party_history": [
                        {"party": 0, "time": "2026-09-01T12:00:00Z", "event": "keyup", "button": "5"}
                    ],
                })),
            ),
        ]
        .into_iter()
        .chain(core_04_violations().into_iter().map(|(label, doc, ..)| (label, doc)))
        .collect()
    }

    /// The verdict this validator would give, reduced to the reference's
    /// question: does anything at all disagree with the schema?
    fn agrees(report: &SchemaReport) -> bool {
        report.errors.is_empty()
    }

    /// This validator answers what a real draft-07 engine answers.
    ///
    /// The subset is the risk: a keyword implemented loosely passes a
    /// container the schema rejects, and nothing in a hand-written expectation
    /// would notice. So the expectation is not hand-written — it is
    /// `jsonschema`, the engine the gates in `tests/` already validate
    /// containers with, run over the same documents.
    #[test]
    fn the_validator_agrees_with_a_reference_implementation() -> Result<(), TestError> {
        // Formats asserted, because this validator asserts them. draft-07
        // leaves `format` annotation-only unless a consumer opts in, and a
        // reference that skipped it would call a container with `start:
        // "yesterday"` valid -- so the comparison would be measuring two
        // different questions.
        let reference = jsonschema::options()
            .should_validate_formats(true)
            .build(schema())
            .map_err(|e| format!("the vendored schema compiles: {e:?}"))?;
        let documents = corpus();
        assert!(
            documents.len() >= 25,
            "the corpus shrank to {}; a comparison over a handful of documents \
             proves almost nothing about a validator",
            documents.len()
        );
        // Both answers must actually occur, or the comparison is satisfied by
        // a validator that always says one thing.
        let expected_valid = documents
            .iter()
            .filter(|(_, d)| reference.is_valid(d))
            .count();
        assert!(
            expected_valid > 0 && expected_valid < documents.len(),
            "the corpus must contain both valid and invalid documents; the \
             reference calls {expected_valid} of {} valid",
            documents.len()
        );

        for (label, document) in &documents {
            let mine = validate(document);
            assert_eq!(
                agrees(&mine),
                reference.is_valid(document),
                "`{label}`: this validator and the reference disagree. \
                 Mine: {:?}. Document: {document:#}",
                mine,
            );
        }
        Ok(())
    }

    /// The vendored schema uses no keyword this validator quietly ignores.
    ///
    /// The tripwire on the subset. Re-vendoring from a later draft is a
    /// correct-looking action that could introduce `additionalProperties` or
    /// `patternProperties`, and a validator that skipped them would keep
    /// answering "valid" while checking less than it used to.
    #[test]
    fn the_vendored_schema_uses_no_keyword_this_validator_ignores() -> Result<(), TestError> {
        let unimplemented = unimplemented_keywords();
        assert!(
            unimplemented.is_empty(),
            "the vendored schema uses keyword(s) this validator does not \
             implement: {unimplemented:?}. Implement them in \
             src/output/vcon_schema.rs -- do NOT add them to the ignore list, \
             which would make every validation certify less than it claims"
        );

        // Anti-vacuity: the walk has to actually be reading the file. An
        // extractor that returned early would produce an empty set too.
        for keyword in [
            "$ref",
            "allOf",
            "anyOf",
            "oneOf",
            "required",
            "enum",
            "dependencies",
            "if",
            "then",
            "not",
        ] {
            assert!(
                SCHEMA_TEXT.contains(&format!("\"{keyword}\"")),
                "`{keyword}` is not in the vendored schema, so the walk above \
                 is not exercising the branch that handles it"
            );
        }
        Ok(())
    }

    /// An unimplemented keyword refuses; it does not pass quietly.
    ///
    /// Proves the guard's EFFECT rather than its predicate. The list above
    /// asserts the file is clean today; this asserts what happens on the day
    /// it is not.
    #[test]
    fn a_keyword_outside_the_implemented_set_is_named_rather_than_ignored() -> Result<(), TestError>
    {
        let mut out = BTreeSet::new();
        walk_keywords(
            &json!({
                "type": "object",
                "properties": {"a": {"type": "string", "additionalProperties": false}},
            }),
            &mut out,
        );
        assert!(
            out.contains("additionalProperties"),
            "a keyword the validator cannot honor must be reported, not \
             skipped: {out:?}"
        );

        let mut tuple = BTreeSet::new();
        walk_keywords(&json!({"items": [{"type": "string"}]}), &mut tuple);
        assert!(
            tuple.contains("items (tuple form)"),
            "tuple validation changes what `items` MEANS and is not \
             implemented: {tuple:?}"
        );
        Ok(())
    }

    /// A schema this validator has outgrown refuses; it does not pass.
    ///
    /// The effect of the guard, not its predicate. The list test above says
    /// the file is clean today; this says what happens on the day it is not,
    /// and it is the assertion that stops a re-vendor from turning every
    /// validation into a green light over constraints nobody read.
    #[test]
    fn a_schema_this_validator_has_outgrown_refuses_rather_than_passing() -> Result<(), TestError> {
        let report = outgrown(
            &[
                "additionalProperties".to_owned(),
                "patternProperties".to_owned(),
            ]
            .into_iter()
            .collect(),
            "https://example.invalid/schema".to_owned(),
        );
        assert_eq!(
            report.verdict,
            SchemaVerdict::Invalid,
            "a validator that cannot read the schema must not certify a \
             container against it: {report:?}"
        );
        assert_eq!(
            report.errors.len(),
            1,
            "one finding, about the validator rather than the container: \
             {report:?}"
        );
        let detail = &report.errors[0].detail;
        for keyword in ["additionalProperties", "patternProperties"] {
            assert!(
                detail.contains(keyword),
                "the refusal must name every keyword it could not honor, or \
                 the next reader has to find them: {detail}"
            );
        }
        assert!(
            detail.contains("Nothing was checked"),
            "and it must say that nothing was checked, because an `invalid` \
             with a list of keywords reads as a container problem: {detail}"
        );
        Ok(())
    }

    /// A container sipnab could write is valid.
    #[test]
    fn a_container_the_schema_accepts_is_valid() -> Result<(), TestError> {
        let report = validate(&with_dialog(
            json!({"type": "recording", "start": "2026-09-01T12:00:00Z"}),
        ));
        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "nothing here departs from the schema: {report:?}"
        );
        assert!(report.errors.is_empty(), "{report:?}");
        assert_eq!(report.schema_path, SCHEMA_PATH);
        assert!(
            report.schema_id.contains("vcon"),
            "the report must name the schema it read: {report:?}"
        );
        Ok(())
    }

    /// The core-03 empty Dialog Object is an ordinary error under core-04.
    ///
    /// core-03's prose allowed it and its schema rejected it, and this
    /// validator reported it as a named deviation. core-04 removed the prose
    /// that allowed it, so there is nothing left to excuse: `{}` is a Dialog
    /// Object missing its required `type`, and the verdict says `invalid`.
    #[test]
    fn the_core_03_empty_dialog_object_is_an_error_under_core_04() -> Result<(), TestError> {
        let report = validate(&with_dialog(json!({})));
        assert_eq!(report.verdict, SchemaVerdict::Invalid, "{report:?}");
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert_eq!(report.errors[0].instance_path, "/dialog/0");
        assert_eq!(report.errors[0].keyword, "required");
        assert!(
            report.errors[0].detail.contains("type"),
            "the error must name the property: {report:?}"
        );
        Ok(())
    }

    /// A `not` finding names the forbidden property in the words the
    /// documentation quotes.
    ///
    /// `docs/mcp-tools.md`, `docs/examples.md` and the REST test show this
    /// detail verbatim, so it is pinned verbatim here.
    #[test]
    fn a_forbidden_property_is_named_verbatim() -> Result<(), TestError> {
        let report = validate(&with_dialog(json!({"type": "transfer", "parties": [0, 1]})));
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert_eq!(
            report.errors[0].detail,
            "carries `parties`, which the schema forbids here"
        );
        Ok(())
    }

    /// The `if`/`then` pair applies only where its condition holds.
    ///
    /// The anti-vacuity half of the per-type rules: a validator that applied
    /// every `then` unconditionally would refuse `parties` on a `recording`
    /// because it is forbidden on a `transfer`.
    #[test]
    fn a_per_type_prohibition_applies_to_its_type_only() -> Result<(), TestError> {
        let report = validate(&with_dialog(
            json!({"type": "recording", "parties": [0, 1]}),
        ));
        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "`parties` is forbidden on `transfer`, not on `recording`: {report:?}"
        );
        let report = validate(&with_dialog(json!({"type": "text", "body": ""})));
        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "an EMPTY body needs no encoding, per core-04 Table 1 note (3): {report:?}"
        );
        Ok(())
    }

    /// The ONE place this validator is stricter than the reference, pinned.
    ///
    /// `jsonschema` compiles without its `uuid` format support, so it treats
    /// `format: uuid` as an annotation and calls `not-a-uuid` valid. This
    /// validator refuses it, and that direction is the safe one: a producer is
    /// told about a malformed identifier rather than not told.
    ///
    /// The case is pinned here rather than dropped, so the exclusion from the
    /// cross-check corpus is a stated fact with a test on it. The day the
    /// reference gains `uuid`, this fails and the case moves back into the
    /// corpus where it belongs.
    #[test]
    fn the_uuid_format_is_enforced_here_and_annotated_by_the_reference() -> Result<(), TestError> {
        let reference = jsonschema::options()
            .should_validate_formats(true)
            .build(schema())
            .map_err(|e| format!("the vendored schema compiles: {e:?}"))?;
        let mut container = minimal();
        container["uuid"] = json!("not-a-uuid");

        assert!(
            reference.is_valid(&container),
            "the reference has gained `uuid` format support -- move this case              back into `corpus()` and delete this test"
        );
        let report = validate(&container);
        assert_eq!(
            report.verdict,
            SchemaVerdict::Invalid,
            "a malformed identifier must be refused here: {report:?}"
        );
        assert_eq!(report.errors[0].keyword, "format", "{report:?}");
        Ok(())
    }

    /// The three formats the schema uses are enforced, not annotated away.
    #[test]
    fn the_formats_the_schema_uses_are_enforced() -> Result<(), TestError> {
        assert!(format_matches("date-time", "2026-09-01T12:00:00Z"));
        assert!(!format_matches("date-time", "2026-09-01"));
        assert!(format_matches(
            "uuid",
            "018f3a2b-4c5d-8e6f-9012-3456789abcde"
        ));
        assert!(!format_matches("uuid", "018f3a2b4c5d8e6f90123456789abcde"));
        assert!(format_matches("uri", "https://example.com/x"));
        assert!(!format_matches("uri", "example.com/x"));
        Ok(())
    }

    /// The example of [core-04 Appendix A.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-A.4),
    /// "Two Party Call vCon With Externally Referenced Recording", verbatim
    /// from `examples/ab_call_ext_rec.vcon` at the `draft-ietf-vcon-vcon-core-04`
    /// tag of the working group's repository.
    ///
    /// The publisher's own conforming container. A validator that refuses it
    /// is checking a rule the draft does not have.
    fn core_04_example_a4() -> Value {
        json!({
            "created_at": "2022-06-21T13:53:00-04:00",
            "parties": [
                {"tel": "+12345678901", "name": "Alice"},
                {"tel": "+19876543210", "name": "Bob"}
            ],
            "dialog": [
                {
                    "type": "recording",
                    "start": "2022-06-21T17:53:26.000+00:00",
                    "duration": 33.12,
                    "parties": [0, 1],
                    "url": "https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core/raw/refs/heads/main/examples/ab_call.mp3",
                    "mediatype": "audio/x-mp3",
                    "filename": "ab_call.mp3",
                    "content_hash": "sha512-GLy6IPaIUM1GqzZqfIPZlWjaDsNgNvZM0iCONNThnH0a75fhUM6cYzLZ5GynSURREvZwmOh54-2lRRieyj82UQ"
                }
            ],
            "analysis": [],
            "attachments": [],
            "uuid": "01a07da8-c2bb-83e5-b9a2-279e0d16bc46"
        })
    }

    /// One container per rule draft-ietf-vcon-vcon-core-04 added, each
    /// breaking exactly that rule, with the pointer and keyword the finding
    /// must carry.
    ///
    /// The section each rule comes from is named beside it. Every one of these
    /// containers was VALID under the `-03` schema, which is what makes the
    /// set discriminate between a validator reading `-03` and one reading
    /// `-04`.
    fn core_04_violations() -> Vec<(
        &'static str,
        Value,
        &'static str,
        &'static str,
        &'static str,
    )> {
        let t = "2026-09-01T12:00:00Z";
        vec![
            (
                // core-04 section 4.3.4: parties MUST NOT be present on transfer.
                "transfer carrying parties",
                with_dialog(json!({"type": "transfer", "start": t, "parties": [0, 1]})),
                "/dialog/0",
                "not",
                "parties",
            ),
            (
                // core-04 section 4.3.12: session_id MUST NOT be present on transfer.
                "transfer carrying session_id",
                with_dialog(json!({"type": "transfer", "session_id": {}})),
                "/dialog/0",
                "not",
                "session_id",
            ),
            (
                // core-04 section 4.3.8: mediatype MUST NOT be present on incomplete.
                "incomplete carrying mediatype",
                with_dialog(json!({
                    "type": "incomplete", "disposition": "busy", "mediatype": "audio/x-wav"
                })),
                "/dialog/0",
                "not",
                "mediatype",
            ),
            (
                // core-04 section 4.3.16: message_id MUST NOT be present on recording-set.
                "recording-set carrying message_id",
                with_dialog(json!({"type": "recording-set", "recordings": [], "message_id": "m"})),
                "/dialog/0",
                "not",
                "message_id",
            ),
            (
                // core-04 section 4.3.14: one UnsignedInt, the array form is gone.
                "transfer_target as an array of indices",
                with_dialog(json!({"type": "transfer", "transfer_target": [1, 2]})),
                "/dialog/0/transfer_target",
                "type",
                "integer",
            ),
            (
                // core-04 section 4.3.14: original is one UnsignedInt.
                "original as an array of indices",
                with_dialog(json!({"type": "transfer", "original": [0]})),
                "/dialog/0/original",
                "type",
                "integer",
            ),
            (
                // core-04 section 4.3.11: an incomplete object MUST carry a disposition.
                "incomplete without a disposition",
                with_dialog(json!({"type": "incomplete"})),
                "/dialog/0",
                "required",
                "disposition",
            ),
            (
                // core-04 section 4.3.6: recordings MUST be present on recording-set.
                "recording-set without recordings",
                with_dialog(json!({"type": "recording-set"})),
                "/dialog/0",
                "required",
                "recordings",
            ),
            (
                // core-04 Table 1 note (3): a non-empty body needs its encoding.
                "dialog body without an encoding",
                with_dialog(json!({"type": "text", "mediatype": "text/plain", "body": "hi"})),
                "/dialog/0",
                "required",
                "encoding",
            ),
            (
                // core-04 section 4.3.8: inline Dialog Content needs a mediatype.
                "dialog body without a mediatype",
                with_dialog(json!({"type": "text", "encoding": "none", "body": "hi"})),
                "/dialog/0",
                "required",
                "mediatype",
            ),
            (
                // core-04 section 2.4.2 via Table 1 note (4): a url needs its content_hash.
                "dialog url without a content_hash",
                with_dialog(json!({"type": "recording", "url": "https://example.com/a.wav"})),
                "/dialog/0",
                "dependencies",
                "content_hash",
            ),
            (
                "attachment body without a mediatype",
                {
                    // core-04 section 4.4.5: inline attachment content needs a mediatype.
                    let mut c = minimal();
                    c["attachments"] = json!([{
                        "start": t, "party": 0, "dialog": 0, "encoding": "none", "body": "x"
                    }]);
                    c
                },
                "/attachments/0",
                "required",
                "mediatype",
            ),
            (
                "analysis body without an encoding",
                {
                    // core-04 Appendix B: a non-empty analysis body needs its encoding.
                    let mut c = minimal();
                    c["analysis"] = json!([{"type": "report", "vendor": "v", "body": "x"}]);
                    c
                },
                "/analysis/0",
                "required",
                "encoding",
            ),
            (
                // core-04 section 4.3.13.1: button is required for keydown and keyup.
                "keydown without a button",
                with_dialog(json!({
                    "type": "recording",
                    "party_history": [{"party": 0, "time": t, "event": "keydown"}],
                })),
                "/dialog/0/party_history/0",
                "required",
                "button",
            ),
            (
                "redacted and amended together",
                {
                    // core-04 section 4.1.8: redacted is mutually exclusive with amended.
                    let mut c = minimal();
                    c["redacted"] = json!({"type": "pii"});
                    c["amended"] = json!({"uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde"});
                    c
                },
                "",
                "not",
                "amended",
            ),
            (
                "amended with neither a uuid nor a url",
                {
                    // core-04 section 4.1.9.1: uuid is optional only beside an external reference.
                    let mut c = minimal();
                    c["amended"] = json!({});
                    c
                },
                "/amended",
                "required",
                "uuid",
            ),
            (
                // core-04 section 4.3.1: every Dialog Object names its type.
                "the core-03 empty Dialog Object",
                with_dialog(json!({})),
                "/dialog/0",
                "required",
                "type",
            ),
        ]
    }

    /// The working group's own core-04 example validates.
    #[test]
    fn the_core_04_appendix_a4_example_is_valid() -> Result<(), TestError> {
        let report = validate(&core_04_example_a4());
        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "the publisher's example must pass the publisher's schema: {report:?}"
        );
        Ok(())
    }

    /// A core-04 placeholder Dialog Object is valid: `type` alone.
    ///
    /// [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3):
    /// "a placeholder Dialog Object which contains only the type parameter".
    /// `start` is a SHOULD in core-04 section 4.3.2, so its absence is no
    /// error; core-03's schema required it.
    #[test]
    fn a_core_04_placeholder_dialog_object_is_valid() -> Result<(), TestError> {
        for placeholder in [
            json!({"type": "recording"}),
            json!({"type": "incomplete", "disposition": "failed"}),
            json!({"type": "transfer", "transferor": 0, "transferee": 1}),
        ] {
            let report = validate(&with_dialog(placeholder.clone()));
            assert_eq!(
                report.verdict,
                SchemaVerdict::Valid,
                "{placeholder} is a shape core-04 permits: {report:?}"
            );
        }
        Ok(())
    }

    /// Each rule core-04 added is enforced, at the right place, by name.
    #[test]
    fn every_rule_core_04_added_is_enforced() -> Result<(), TestError> {
        for (label, container, path, keyword, names) in core_04_violations() {
            let report = validate(&container);
            assert_eq!(
                report.verdict,
                SchemaVerdict::Invalid,
                "`{label}` breaks a core-04 rule and must be refused: {report:?}"
            );
            assert!(
                report.errors.iter().any(|e| e.instance_path == path
                    && e.keyword == keyword
                    && e.detail.contains(names)),
                "`{label}`: expected a `{keyword}` finding at `{path}` naming \
                 `{names}`, got {:?}",
                report.errors
            );
        }
        Ok(())
    }
}
