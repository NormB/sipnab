// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-Schema validation helpers (verification plan M1 — T1.3).
//!
//! Loads versioned schemas from `tests/schemas/` and validates serialized
//! output against them. Used to pin sipnab's machine-readable contracts
//! (`--json` NDJSON messages, `--call-report --json`, and — from M3 — the REST
//! API dialog/stream objects). See spec §13.3: schemas must *reject* malformed
//! input, so every schema has an accompanying negative test.

use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde_json::Value;

/// Absolute path to a schema file under `tests/schemas/`.
pub fn schema_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/schemas")
        .join(name)
}

/// Read + compile a schema file into a reusable validator.
///
/// Panics (with the file path) on read / parse / compile failure — a malformed
/// schema is a test-authoring bug that should fail loudly.
pub fn load_validator(schema_file: &str) -> Validator {
    let path = schema_path(schema_file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read schema {}: {e}", path.display()));
    let schema: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parse schema {}: {e}", path.display()));
    jsonschema::validator_for(&schema)
        .unwrap_or_else(|e| panic!("compile schema {}: {e}", path.display()))
}

/// Assert `instance` validates, panicking with every error (path + message) on
/// failure so a schema mismatch is actionable.
pub fn assert_valid(validator: &Validator, instance: &Value, ctx: &str) {
    if !validator.is_valid(instance) {
        let errors: Vec<String> = validator
            .iter_errors(instance)
            .map(|e| format!("  at `{}`: {e}", e.instance_path()))
            .collect();
        panic!("{ctx}: instance failed schema:\n{}", errors.join("\n"));
    }
}

/// Every JSON path in `value` whose leaf is `null`, deepest-first.
///
/// The vCon container documents "an absent field, never a null"
/// (`docs/internals/vcon.md`), and that contract is what a lost
/// `#[serde(skip_serializing_if = "Option::is_none")]` breaks. The loss is
/// otherwise silent: the struct still compiles, the field is still `None`, and
/// only the wire changes — from an absent key to an explicit `null` that a
/// consumer must now distinguish from a value.
///
/// Returns paths rather than a bool so a failure names the field.
///
/// `allow(dead_code)` because `tests/support/` is included by many test
/// binaries and each one uses a different slice of it; only the vCon tests
/// call this. Without it, every feature combo that does not build those tests
/// fails under CI's `-Dwarnings` -- which is exactly how this helper was
/// caught, by `scripts/check-feature-matrix.py`, before it left the machine.
#[allow(dead_code)]
pub fn null_paths(value: &Value) -> Vec<String> {
    fn walk(v: &Value, path: &str, out: &mut Vec<String>) {
        match v {
            Value::Null => out.push(path.to_string()),
            Value::Object(map) => {
                for (k, child) in map {
                    let next = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    walk(child, &next, out);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "", &mut out);
    out
}

/// Validate `instance` against one named schema inside a vendored OpenAPI
/// document, returning the errors as strings.
///
/// An OpenAPI document is not itself a JSON Schema: the schemas live under
/// `components/schemas` and refer to each other with `#/components/schemas/X`
/// pointers. Validating a sub-schema in isolation breaks every one of those
/// references, so this wraps the ENTIRE document around a `$ref` entry point —
/// the pointers then resolve against the document they were written for.
///
/// Errors come back as strings rather than as a pass/fail, because a second
/// consumer's schema is not a gate. Some of its demands are ones this project
/// has considered and declined, and a caller needs to say which failures it
/// expects.
/// `allow(dead_code)` for the reason [`null_paths`] records: `tests/support/`
/// is compiled into every test binary and each uses a different slice, so a
/// helper only the vCon contract tests call fails every other feature combo
/// under CI's `-Dwarnings`.
#[allow(dead_code)]
pub fn openapi_errors(doc_file: &str, schema_name: &str, instance: &Value) -> Vec<String> {
    let path = schema_path(doc_file);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    let mut wrapper = serde_json::json!({
        "$ref": format!("#/components/schemas/{schema_name}"),
    });
    wrapper["components"] = doc["components"].clone();

    let validator = jsonschema::validator_for(&wrapper)
        .unwrap_or_else(|e| panic!("compile {schema_name} from {}: {e}", path.display()));
    validator
        .iter_errors(instance)
        .map(|e| format!("at `{}`: {e}", e.instance_path()))
        .collect()
}
