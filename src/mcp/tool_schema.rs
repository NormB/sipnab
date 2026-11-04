// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab://schema/{tool}`: one tool's response shape, read on demand.
//!
//! Output schemas are off on `tools/list` unless the operator turns them on
//! (`--mcp-output-schemas`), because they are most of what the tool list
//! costs a client's context. A client that wants to know what one tool
//! returns reads this resource instead: the tool's output JSON Schema when it
//! declares one, and one example payload that validates against it. For a
//! tool that declares no schema, the body says so.
//!
//! The example is SYNTHESIZED from the schema by [`example`], not taken from a
//! capture. Every value is a placeholder of the declared type, so the example
//! shows the shape and nothing about any call. Synthesizing it means it cannot
//! drift from the schema: a hand-written example per tool would be a second
//! copy of every response shape, and nothing would hold the two together.

use serde_json::{Map, Value};

/// Prefix of every URI this module answers.
pub const SCHEMA_URI_PREFIX: &str = "sipnab://schema/";

/// Nesting depth past which [`example`] stops descending.
///
/// A `$ref` cycle (a type that contains itself) has no finite example with
/// every optional member filled in. Past this depth an optional member is left
/// out and an array is left empty, which every schema here accepts.
const MAX_DEPTH: usize = 12;

/// Depth past which even a required `$ref` is not followed.
///
/// Reached only by a schema whose cycle is required, which describes no finite
/// value; it keeps such a schema from recursing without end.
const HARD_DEPTH: usize = 4 * MAX_DEPTH;

/// The body `sipnab://schema/<tool>` returns.
///
/// # Arguments
///
/// * `tool` — the tool name, as loaded.
/// * `output_schema` — the tool's output schema, or `None` when it declares
///   none.
#[must_use]
pub fn describe(tool: &str, output_schema: Option<&Map<String, Value>>) -> Value {
    match output_schema {
        Some(schema) => {
            let schema = Value::Object(schema.clone());
            let example = example(&schema);
            serde_json::json!({
                "schema_version": 1,
                "tool": tool,
                "has_output_schema": true,
                "output_schema": schema,
                "example": example,
                "note": "the example is generated from output_schema: every value \
                         is a placeholder of the declared type, not data from the \
                         loaded capture",
            })
        }
        None => serde_json::json!({
            "schema_version": 1,
            "tool": tool,
            "has_output_schema": false,
            "output_schema": null,
            "example": null,
            "note": format!(
                "{tool} declares no output schema, so there is no machine-checkable \
                 response shape to return. Its response is described in the {tool} \
                 section of the MCP tool reference: docs/mcp-tools.md names the \
                 bundle page that holds it"
            ),
        }),
    }
}

/// One instance of `schema`, built from the schema alone.
///
/// Every property is filled in, required or not, so the example shows every
/// key a response can carry. `$ref` is resolved against the schema's own
/// `$defs` (or `definitions`).
#[must_use]
pub fn example(schema: &Value) -> Value {
    instance(schema, schema, 0)
}

/// [`example`] for `node`, resolving references against `root`.
fn instance(node: &Value, root: &Value, depth: usize) -> Value {
    let Some(obj) = node.as_object() else {
        // `true` (anything) or `false` (nothing): null is as good as any.
        return Value::Null;
    };
    if let Some(target) = obj.get("$ref").and_then(Value::as_str) {
        // Resolved past `MAX_DEPTH` too: a member that reaches a reference is
        // one the parent kept (required, or not yet past the depth), and a
        // required member left null is an example its own schema rejects.
        // What ends a cycle is the optional branch taken below, and
        // `HARD_DEPTH` ends a schema whose cycle is required, which no finite
        // value has.
        return match resolve(root, target) {
            Some(resolved) if depth < HARD_DEPTH => instance(resolved, root, depth + 1),
            _ => Value::Null,
        };
    }
    if let Some(value) = obj.get("const") {
        return value.clone();
    }
    if let Some(first) = obj
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        return first.clone();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(branches) = obj.get(key).and_then(Value::as_array) {
            // Past the depth an optional value is shown absent, which is how
            // a self-reference such as `Option<Box<Self>>` ends.
            if depth >= MAX_DEPTH
                && branches
                    .iter()
                    .any(|b| b.get("type").and_then(Value::as_str) == Some("null"))
            {
                return Value::Null;
            }
            // The first branch that is not bare `null`, so an optional value
            // is shown with its content rather than as absent.
            let branch = branches
                .iter()
                .find(|b| b.get("type").and_then(Value::as_str) != Some("null"))
                .or_else(|| branches.first());
            if let Some(branch) = branch {
                return instance(branch, root, depth + 1);
            }
        }
    }
    if let Some(parts) = obj.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for part in parts {
            if let Value::Object(fields) = instance(part, root, depth + 1) {
                merged.extend(fields);
            }
        }
        return Value::Object(merged);
    }
    match type_of(obj) {
        Some("object") => object(obj, root, depth),
        Some("array") => array(obj, root, depth),
        Some("string") => string(obj),
        Some("integer") => Value::from(integer(obj)),
        Some("number") => Value::from(integer(obj)),
        Some("boolean") => Value::Bool(false),
        _ => Value::Null,
    }
}

/// The node's type: its `type` string, the first non-null entry of a `type`
/// array, or `object` when it has properties and no `type`.
fn type_of(obj: &Map<String, Value>) -> Option<&str> {
    match obj.get("type") {
        Some(Value::String(t)) => Some(t.as_str()),
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null")
            .or(Some("null")),
        _ if obj.contains_key("properties") => Some("object"),
        _ => None,
    }
}

/// An object with every declared property filled in.
fn object(obj: &Map<String, Value>, root: &Value, depth: usize) -> Value {
    let required: Vec<&str> = obj
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = Map::new();
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for (name, child) in props {
            if depth >= MAX_DEPTH && !required.contains(&name.as_str()) {
                continue;
            }
            out.insert(name.clone(), instance(child, root, depth + 1));
        }
    }
    Value::Object(out)
}

/// An array holding one example item, or none past [`MAX_DEPTH`].
fn array(obj: &Map<String, Value>, root: &Value, depth: usize) -> Value {
    if let Some(prefix) = obj.get("prefixItems").and_then(Value::as_array) {
        return Value::Array(
            prefix
                .iter()
                .map(|p| instance(p, root, depth + 1))
                .collect(),
        );
    }
    match obj.get("items") {
        Some(items) if depth < MAX_DEPTH => Value::Array(vec![instance(items, root, depth + 1)]),
        _ => Value::Array(Vec::new()),
    }
}

/// A placeholder string honoring the defined `format` values and `minLength`.
fn string(obj: &Map<String, Value>) -> Value {
    let by_format = match obj.get("format").and_then(Value::as_str) {
        Some("date-time") => Some("1970-01-01T00:00:00Z"),
        Some("date") => Some("1970-01-01"),
        Some("time") => Some("00:00:00Z"),
        Some("ipv4") => Some("192.0.2.1"),
        Some("ipv6") => Some("2001:db8::1"),
        Some("uri") => Some("https://example.invalid/"),
        Some("uuid") => Some("00000000-0000-0000-0000-000000000000"),
        Some("email") => Some("user@example.invalid"),
        Some("hostname") => Some("example.invalid"),
        _ => None,
    };
    if let Some(s) = by_format {
        return Value::String(s.to_string());
    }
    let min = obj.get("minLength").and_then(Value::as_u64).unwrap_or(0);
    let text = "string";
    let len = usize::try_from(min).unwrap_or(0).max(text.len());
    Value::String(text.chars().cycle().take(len).collect())
}

/// The smallest integer the node's bounds allow, or zero.
fn integer(obj: &Map<String, Value>) -> i64 {
    if let Some(min) = obj.get("minimum").and_then(Value::as_f64) {
        return min.ceil() as i64;
    }
    if let Some(min) = obj.get("exclusiveMinimum").and_then(Value::as_f64) {
        return min.floor() as i64 + 1;
    }
    0
}

/// The node a local `$ref` (`#/$defs/Name` or `#/definitions/Name`) names.
fn resolve<'a>(root: &'a Value, target: &str) -> Option<&'a Value> {
    let pointer = target.strip_prefix('#')?;
    root.pointer(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type TestError = Box<dyn std::error::Error>;

    /// The example for `schema` must validate against `schema`.
    fn assert_valid(schema: &Value) -> Result<Value, TestError> {
        let example = example(schema);
        let validator = jsonschema::validator_for(schema)?;
        if let Err(e) = validator.validate(&example) {
            return Err(format!("example {example} does not match {schema}: {e}").into());
        }
        Ok(example)
    }

    #[test]
    fn every_property_is_filled_and_refs_resolve() -> Result<(), TestError> {
        let schema = json!({
            "type": "object",
            "required": ["n", "inner"],
            "properties": {
                "n": {"type": "integer", "minimum": 3},
                "s": {"type": ["string", "null"]},
                "kind": {"type": "string", "enum": ["b", "c"]},
                "inner": {"$ref": "#/$defs/Inner"},
                "list": {"type": "array", "items": {"$ref": "#/$defs/Inner"}},
                "either": {"oneOf": [{"type": "null"}, {"const": "x"}]}
            },
            "$defs": {"Inner": {"type": "object", "properties": {"b": {"type": "boolean"}}}}
        });
        let e = assert_valid(&schema)?;
        assert_eq!(
            e,
            json!({
                "n": 3,
                "s": "string",
                "kind": "b",
                "inner": {"b": false},
                "list": [{"b": false}],
                "either": "x"
            })
        );
        Ok(())
    }

    #[test]
    fn a_self_referencing_type_still_ends() -> Result<(), TestError> {
        let schema = json!({
            "type": "object",
            "properties": {"node": {"$ref": "#/$defs/Node"}},
            "$defs": {"Node": {
                "type": "object",
                "properties": {"children": {"type": "array", "items": {"$ref": "#/$defs/Node"}}}
            }}
        });
        assert_valid(&schema)?;
        Ok(())
    }

    /// A chain of required references deeper than `MAX_DEPTH` is still
    /// filled in to its leaf: a required member left `null` is an example its
    /// own schema rejects. The relay sessions answer nests a socket's
    /// counters this deep.
    #[test]
    fn a_required_reference_past_the_depth_is_still_filled_in() -> Result<(), TestError> {
        let mut defs = serde_json::Map::new();
        let levels = MAX_DEPTH + 6;
        for i in 0..levels {
            defs.insert(
                format!("L{i}"),
                json!({
                    "type": "object",
                    "required": ["next"],
                    "properties": {"next": {"$ref": format!("#/$defs/L{}", i + 1)}}
                }),
            );
        }
        defs.insert(
            format!("L{levels}"),
            json!({"type": "string", "enum": ["leaf"]}),
        );
        let schema = json!({"$ref": "#/$defs/L0", "$defs": defs});
        let mut e = assert_valid(&schema)?;
        for _ in 0..levels {
            e = e["next"].clone();
        }
        assert_eq!(e, json!("leaf"), "the deepest required member is filled in");
        Ok(())
    }

    /// An optional self-reference, `Option<Box<Self>>`'s `anyOf` with `null`,
    /// still ends: past the depth the optional member takes its `null`
    /// branch.
    #[test]
    fn an_optional_self_reference_still_ends() -> Result<(), TestError> {
        let schema = json!({
            "$ref": "#/$defs/Node",
            "$defs": {"Node": {
                "type": "object",
                "required": ["next"],
                "properties": {"next": {"anyOf": [{"$ref": "#/$defs/Node"}, {"type": "null"}]}}
            }}
        });
        let mut e = assert_valid(&schema)?;
        let mut nested = 0;
        while e.get("next").is_some_and(|n| !n.is_null()) {
            e = e["next"].clone();
            nested += 1;
        }
        assert!(
            nested <= MAX_DEPTH,
            "the optional member ends at the depth, not at the hard stop: {nested} levels"
        );
        Ok(())
    }

    #[test]
    fn a_tool_without_a_schema_says_so() -> Result<(), TestError> {
        let body = describe("render_ladder", None);
        assert_eq!(body["has_output_schema"], json!(false));
        assert!(body["output_schema"].is_null() && body["example"].is_null());
        assert!(
            body["note"]
                .as_str()
                .is_some_and(|n| n.contains("no output schema"))
        );
        Ok(())
    }
}
