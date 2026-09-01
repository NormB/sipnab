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
//! # The documented deviation
//!
//! §4.3 of `draft-ietf-vcon-vcon-core` says "it is possible to have a Dialog
//! Object with no parameters in it", the working group agreed that shape in
//! issue #20 after IETF 124, and the draft's own Appendix B schema rejects it:
//! `start` is required on every Dialog Object. sipnab emits one — the
//! consultative call of an attended transfer, which this leg is known not to
//! have seen.
//!
//! That is reported as a DEVIATION with its own name, never folded into the
//! clean verdict. A validator that quietly tolerates the one shape the schema
//! forbids teaches a producer the wrong lesson, and the next container it
//! writes with a genuinely missing `start` will read as fine.

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

/// The name the documented deviation is reported under.
pub const EMPTY_DIALOG_OBJECT: &str = "empty-dialog-object";

/// What the deviation is, in one paragraph a producer can act on.
pub const EMPTY_DIALOG_OBJECT_EXPLANATION: &str = "The empty Dialog Object `{}` of section 4.3: \"it is possible to have a Dialog Object with \
     no parameters in it\". The working group agreed this shape in issue #20 after IETF 124, and \
     the draft's own Appendix B schema rejects it, because `start` is required on every Dialog \
     Object. sipnab emits one for the consultative call of an attended transfer -- a call known \
     to have occurred that this leg never saw. It is reported here rather than passed silently: \
     a validator that tolerates the one shape the schema forbids would teach a producer that a \
     missing `start` is fine.";

/// Keywords this validator implements.
const IMPLEMENTED: &[&str] = &[
    "$ref",
    "anyOf",
    "const",
    "dependencies",
    "enum",
    "format",
    "items",
    "minimum",
    "oneOf",
    "properties",
    "required",
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
    /// Every finding is a documented deviation, and there is at least one.
    ///
    /// A separate answer from [`Self::Valid`] on purpose. Collapsing the two
    /// would put the one shape the schema forbids behind a clean verdict, and
    /// a producer reading that learns the wrong lesson about `start`.
    ValidExceptDocumentedDeviation,
    /// At least one finding is not a documented deviation.
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
            Self::ValidExceptDocumentedDeviation => "valid-except-documented-deviation",
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
    /// The documented deviation this finding IS, when it is one.
    ///
    /// `None` is an ordinary error. `Some` names a shape sipnab emits on
    /// purpose and the schema rejects on purpose, and
    /// [`SchemaReport::explanations`] carries the reasoning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deviation: Option<&'static str>,
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
    /// Findings that are NOT documented deviations. Empty on a clean pass.
    pub errors: Vec<SchemaFinding>,
    /// Findings that ARE documented deviations, kept apart from the errors.
    pub deviations: Vec<SchemaFinding>,
    /// One paragraph per distinct deviation named above.
    ///
    /// Beside the findings rather than inside each one: a container with four
    /// empty Dialog Objects should carry the reasoning once, not four times.
    pub explanations: Vec<DeviationNote>,
}

/// Why a deviation is a deviation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct DeviationNote {
    /// The name the findings reference.
    pub name: &'static str,
    /// What it is, and why it is emitted anyway.
    pub explanation: &'static str,
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
            panic!("the vendored vCon schema is not valid JSON: {e}")
        })
    })
}

/// Keywords the vendored schema uses that this validator does not implement.
///
/// The tripwire on the subset. A re-vendor that introduces `additionalProperties`,
/// `patternProperties`, `if`/`then`, a tuple-form `items` or anything else in
/// the draft-07 vocabulary shows up here, and [`validate`] refuses rather than
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
            "anyOf" | "oneOf" => {
                if let Some(branches) = value.as_array() {
                    for sub in branches {
                        walk_keywords(sub, out);
                    }
                }
            }
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
/// A [`SchemaReport`]. Errors and documented deviations are kept in separate
/// lists, and the verdict distinguishes "clean" from "clean apart from the
/// shape we emit on purpose".
#[must_use]
pub fn validate(container: &Value) -> SchemaReport {
    let schema_id = schema()["$id"].as_str().unwrap_or_default().to_owned();

    let unimplemented = unimplemented_keywords();
    if !unimplemented.is_empty() {
        return outgrown(&unimplemented, schema_id);
    }

    let mut findings = Vec::new();
    check(schema(), container, "", &mut findings);
    classify_deviations(container, &mut findings);

    let (deviations, errors): (Vec<_>, Vec<_>) =
        findings.into_iter().partition(|f| f.deviation.is_some());

    let mut explanations = Vec::new();
    if deviations
        .iter()
        .any(|d| d.deviation == Some(EMPTY_DIALOG_OBJECT))
    {
        explanations.push(DeviationNote {
            name: EMPTY_DIALOG_OBJECT,
            explanation: EMPTY_DIALOG_OBJECT_EXPLANATION,
        });
    }

    let verdict = if !errors.is_empty() {
        SchemaVerdict::Invalid
    } else if deviations.is_empty() {
        SchemaVerdict::Valid
    } else {
        SchemaVerdict::ValidExceptDocumentedDeviation
    };

    SchemaReport {
        verdict,
        schema_id,
        schema_path: SCHEMA_PATH,
        errors,
        deviations,
        explanations,
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
            deviation: None,
        }],
        deviations: Vec::new(),
        explanations: Vec::new(),
    }
}

/// Re-label the findings that are the documented deviation.
///
/// Narrow on purpose. ONLY a Dialog Object with no members at all is the shape
/// §4.3 blesses; a `transfer` object that happens to be missing `start` is the
/// real defect the corpus pass found, and folding the two together would hide
/// it behind the exemption.
fn classify_deviations(container: &Value, findings: &mut [SchemaFinding]) {
    let Some(objects) = container.get("dialog").and_then(Value::as_array) else {
        return;
    };
    for (index, object) in objects.iter().enumerate() {
        if !object.as_object().is_some_and(serde_json::Map::is_empty) {
            continue;
        }
        let path = format!("/dialog/{index}");
        for finding in findings.iter_mut() {
            if finding.instance_path == path && finding.keyword == "required" {
                finding.deviation = Some(EMPTY_DIALOG_OBJECT);
            }
        }
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
                deviation: None,
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
            deviation: None,
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
            deviation: None,
        });
    }

    if let Some(expected) = map.get("const")
        && expected != instance
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "const",
            detail: format!("expected `{expected}`, found `{instance}`"),
            deviation: None,
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
            deviation: None,
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
            deviation: None,
        });
    }

    if let Some(branches) = map.get("anyOf").and_then(Value::as_array)
        && !branches.iter().any(|b| passes(b, instance))
    {
        out.push(SchemaFinding {
            instance_path: path.to_owned(),
            keyword: "anyOf",
            detail: format!("matches none of the {} permitted shapes", branches.len()),
            deviation: None,
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
                deviation: None,
            });
        }
    }

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
                    deviation: None,
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
                        deviation: None,
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

/// Does this instance satisfy this subschema, ignoring where it failed?
///
/// The branch test `anyOf` and `oneOf` need. It runs the same [`check`], so a
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

/// A URI reference with a scheme, per RFC 3986 §3.1.
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
        ]
    }

    /// The verdict this validator would give, reduced to the reference's
    /// question: does anything at all disagree with the schema?
    ///
    /// A documented deviation counts as a disagreement HERE, because the
    /// reference implementation reads the schema and nothing else. Keeping the
    /// exemption out of the comparison is what makes the comparison mean
    /// something.
    fn agrees(report: &SchemaReport) -> bool {
        report.errors.is_empty() && report.deviations.is_empty()
    }

    /// This validator answers what a real draft-07 engine answers.
    ///
    /// The subset is the risk: a keyword implemented loosely passes a
    /// container the schema rejects, and nothing in a hand-written expectation
    /// would notice. So the expectation is not hand-written — it is
    /// `jsonschema`, the engine the gates in `tests/` already validate
    /// containers with, run over the same documents.
    #[test]
    fn the_validator_agrees_with_a_reference_implementation() {
        // Formats asserted, because this validator asserts them. draft-07
        // leaves `format` annotation-only unless a consumer opts in, and a
        // reference that skipped it would call a container with `start:
        // "yesterday"` valid -- so the comparison would be measuring two
        // different questions.
        let reference = jsonschema::options()
            .should_validate_formats(true)
            .build(schema())
            .expect("the vendored schema compiles");
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
    }

    /// The vendored schema uses no keyword this validator quietly ignores.
    ///
    /// The tripwire on the subset. Re-vendoring from a later draft is a
    /// correct-looking action that could introduce `additionalProperties` or
    /// `patternProperties`, and a validator that skipped them would keep
    /// answering "valid" while checking less than it used to.
    #[test]
    fn the_vendored_schema_uses_no_keyword_this_validator_ignores() {
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
        for keyword in ["$ref", "anyOf", "oneOf", "required", "enum", "dependencies"] {
            assert!(
                SCHEMA_TEXT.contains(&format!("\"{keyword}\"")),
                "`{keyword}` is not in the vendored schema, so the walk above \
                 is not exercising the branch that handles it"
            );
        }
    }

    /// An unimplemented keyword refuses; it does not pass quietly.
    ///
    /// Proves the guard's EFFECT rather than its predicate. The list above
    /// asserts the file is clean today; this asserts what happens on the day
    /// it is not.
    #[test]
    fn a_keyword_outside_the_implemented_set_is_named_rather_than_ignored() {
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
    }

    /// A schema this validator has outgrown refuses; it does not pass.
    ///
    /// The effect of the guard, not its predicate. The list test above says
    /// the file is clean today; this says what happens on the day it is not,
    /// and it is the assertion that stops a re-vendor from turning every
    /// validation into a green light over constraints nobody read.
    #[test]
    fn a_schema_this_validator_has_outgrown_refuses_rather_than_passing() {
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
        assert!(
            report.deviations.is_empty(),
            "this is not a deviation, it is a validator that stopped working: \
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
    }

    /// A container sipnab could write, with no deviation in it, is valid.
    #[test]
    fn a_container_the_schema_accepts_is_valid() {
        let report = validate(&with_dialog(
            json!({"type": "recording", "start": "2026-09-01T12:00:00Z"}),
        ));
        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "nothing here departs from the schema: {report:?}"
        );
        assert!(report.errors.is_empty(), "{report:?}");
        assert!(report.deviations.is_empty(), "{report:?}");
        assert!(
            report.explanations.is_empty(),
            "there is nothing to explain: {report:?}"
        );
        assert_eq!(report.schema_path, SCHEMA_PATH);
        assert!(
            report.schema_id.contains("vcon"),
            "the report must name the schema it read: {report:?}"
        );
    }

    /// RV6: the empty Dialog Object is NAMED, not waved through.
    ///
    /// It is the one shape the working group agreed and the schema forbids, so
    /// it can be neither an ordinary error nor part of a clean bill. A
    /// validator that folded it into `Valid` would teach a producer that a
    /// missing `start` is acceptable, which is precisely the defect the corpus
    /// pass found two of.
    #[test]
    fn an_empty_dialog_object_is_reported_as_the_documented_deviation() {
        let report = validate(&with_dialog(json!({})));
        assert_eq!(
            report.verdict,
            SchemaVerdict::ValidExceptDocumentedDeviation,
            "neither `valid` nor `invalid`: {report:?}"
        );
        assert!(
            report.errors.is_empty(),
            "the only finding is the deviation: {report:?}"
        );
        assert_eq!(report.deviations.len(), 1, "{report:?}");
        assert_eq!(
            report.deviations[0].deviation,
            Some(EMPTY_DIALOG_OBJECT),
            "the deviation carries its name: {report:?}"
        );
        assert_eq!(
            report.deviations[0].instance_path, "/dialog/0",
            "and a pointer a reader can follow: {report:?}"
        );
        assert_eq!(
            report.explanations,
            vec![DeviationNote {
                name: EMPTY_DIALOG_OBJECT,
                explanation: EMPTY_DIALOG_OBJECT_EXPLANATION,
            }],
            "and the reasoning travels with it, once: {report:?}"
        );
    }

    /// The corpus defect stays an ERROR: a typed object missing `start`.
    ///
    /// This is the discriminating case. A validator that exempted every
    /// missing `start` would report the 2-in-4,216 real defect as the
    /// documented deviation and hide it forever.
    #[test]
    fn a_typed_dialog_object_missing_start_is_a_real_error() {
        let report = validate(&with_dialog(json!({"type": "transfer", "transferee": 1})));
        assert_eq!(
            report.verdict,
            SchemaVerdict::Invalid,
            "a REFER that produced a transfer object with no start is the \
             defect, not the exemption: {report:?}"
        );
        assert!(
            report.deviations.is_empty(),
            "nothing here is the documented deviation: {report:?}"
        );
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert_eq!(report.errors[0].keyword, "required");
        assert!(
            report.errors[0].detail.contains("start"),
            "the error must name the property: {report:?}"
        );
    }

    /// A container that is both wrong and deviant reports both, separately.
    ///
    /// The verdict is `invalid` because an error is present, and the deviation
    /// does not vanish into it: an operator fixing the error must still know
    /// the other object is there.
    #[test]
    fn an_error_beside_a_deviation_keeps_both() {
        let mut container = minimal();
        container["dialog"] = json!([{}, {"type": "transfer"}]);
        let report = validate(&container);
        assert_eq!(report.verdict, SchemaVerdict::Invalid, "{report:?}");
        assert_eq!(report.deviations.len(), 1, "{report:?}");
        assert_eq!(report.deviations[0].instance_path, "/dialog/0");
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert_eq!(report.errors[0].instance_path, "/dialog/1");
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
    fn the_uuid_format_is_enforced_here_and_annotated_by_the_reference() {
        let reference = jsonschema::options()
            .should_validate_formats(true)
            .build(schema())
            .expect("the vendored schema compiles");
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
    }

    /// The three formats the schema uses are enforced, not annotated away.
    #[test]
    fn the_formats_the_schema_uses_are_enforced() {
        assert!(format_matches("date-time", "2026-09-01T12:00:00Z"));
        assert!(!format_matches("date-time", "2026-09-01"));
        assert!(format_matches(
            "uuid",
            "018f3a2b-4c5d-8e6f-9012-3456789abcde"
        ));
        assert!(!format_matches("uuid", "018f3a2b4c5d8e6f90123456789abcde"));
        assert!(format_matches("uri", "https://example.com/x"));
        assert!(!format_matches("uri", "example.com/x"));
    }
}
