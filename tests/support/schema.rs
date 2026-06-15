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
