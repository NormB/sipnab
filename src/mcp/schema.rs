// SPDX-License-Identifier: MIT OR Apache-2.0

//! Making advertised tool schemas portable across MCP clients.
//!
//! `schemars` renders `Option<T>` as `"type": ["T", "null"]`. That is legal
//! JSON Schema and it is what every draft since 2019-09 says a nullable value
//! looks like. It is also a spelling several MCP clients cannot read: they
//! take `type` as a single string and either drop the constraint or refuse the
//! whole tool. A refused tool is not a degraded tool — the agent simply does
//! not have it.
//!
//! The MCP Inspector's `--strict` lint reported 172 findings across 47 tools
//! on 0.5.160, and 169 of them are this one shape. So the schemas are
//! normalized once, where the router is assembled, rather than by annotating
//! several hundred fields.
//!
//! **What the rewrite costs, said plainly.** `["string","null"]` accepts an
//! explicit `null`; `"string"` does not. Collapsing therefore advertises a
//! schema slightly NARROWER than the tool accepts — sipnab's serde
//! deserialization still takes `null` for an `Option<T>`, and a caller that
//! omits the key entirely was always the ordinary path. Nothing that
//! validated before stops working; what changes is that a client can no longer
//! be told, by the schema, that `{"filter": null}` is valid.
//!
//! **A REQUIRED nullable is left alone**, because there the union is the only
//! thing that says how to send the key empty. Collapsing it would advertise a
//! schema forbidding a value the tool must accept, which is a worse defect
//! than the one being fixed.

use std::collections::BTreeSet;

use serde_json::Value;

/// Apply [`make_portable`] to every tool's INPUT schema.
///
/// The single choke point. The alternative is annotating several hundred
/// fields, which is the same rule written several hundred times and then
/// forgotten on the next one.
///
/// # Why input schemas only
///
/// An input schema describes what a caller may SEND, and a caller that has
/// nothing to send omits the key. An output schema describes what sipnab
/// itself sends, and sipnab writes an explicit `null` for an absent optional
/// field — so collapsing there would advertise a schema its own responses
/// violate. `every_declared_output_schema_matches_the_payload_it_describes`
/// proved exactly that within a minute of the first draft, which is the
/// difference between a portability fix and a lie about the wire.
///
/// The input side is also where the cost of the unusual spelling falls: a
/// client validates arguments before calling, and one that refuses the tool
/// refuses it there.
///
/// # Arguments
///
/// * `router` — the assembled router, consumed and returned so the call site
///   reads as one step of the composition rather than as a mutation somebody
///   can forget to perform.
///
/// # Returns
///
/// The same router, with every input schema rewritten and every output schema
/// untouched.
#[must_use]
pub fn portable_router<S>(
    mut router: rmcp::handler::server::router::tool::ToolRouter<S>,
) -> rmcp::handler::server::router::tool::ToolRouter<S> {
    for route in router.map.values_mut() {
        let mut input = serde_json::Value::Object((*route.attr.input_schema).clone());
        if make_portable(&mut input) > 0
            && let serde_json::Value::Object(obj) = input
        {
            route.attr.input_schema = std::sync::Arc::new(obj);
        }
    }
    router
}

/// Rewrite `["T","null"]` into `"T"` wherever the property is optional.
///
/// # Arguments
///
/// * `schema` — a whole tool input or output schema, rewritten in place.
///
/// # Returns
///
/// How many type unions were collapsed. A caller that expects the pass to do
/// something can assert on it rather than trusting that it ran.
pub fn make_portable(schema: &mut Value) -> usize {
    let mut changed = 0;
    walk(schema, false, &mut changed, true);
    changed
}

/// How many unions [`make_portable`] WOULD collapse, without touching them.
///
/// The gate's half. A test can ask a live server "is anything left" without
/// mutating the schema it is asking about.
#[must_use]
pub fn portable_count(schema: &Value) -> usize {
    let mut probe = schema.clone();
    make_portable(&mut probe)
}

/// The single type behind a nullable union, when there is exactly one.
///
/// `None` for anything else: a union without `"null"` is a real union, and one
/// with three members has no single type to collapse to — picking one would
/// silently drop the others.
fn nullable_single_type(ty: &Value) -> Option<String> {
    let items = ty.as_array()?;
    if items.len() != 2 {
        return None;
    }
    let mut concrete = None;
    let mut saw_null = false;
    for item in items {
        match item.as_str()? {
            "null" => saw_null = true,
            other => concrete = Some(other.to_string()),
        }
    }
    if saw_null { concrete } else { None }
}

/// Walk one schema node.
///
/// # Arguments
///
/// * `node` — the schema being visited.
/// * `optional` — whether the node describes a property its parent object
///   leaves out of `required`. Only an optional property may be collapsed.
/// * `changed` — running count of collapses.
/// * `_root` — retained so the entry point reads as a walk rather than a
///   special case; the rule does not differ at the root.
fn walk(node: &mut Value, optional: bool, changed: &mut usize, _root: bool) {
    let Some(obj) = node.as_object_mut() else {
        return;
    };

    if optional && let Some(single) = obj.get("type").and_then(nullable_single_type) {
        obj.insert("type".into(), Value::String(single));
        *changed += 1;
    }

    // The `required` list belongs to THIS object and decides its own
    // properties, so it is read before descending rather than threaded down.
    let required: BTreeSet<String> = obj
        .get("required")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    if let Some(props) = obj.get_mut("properties").and_then(Value::as_object_mut) {
        for (name, child) in props.iter_mut() {
            walk(child, !required.contains(name), changed, false);
        }
    }

    // Everything else is a schema position rather than a named property, so
    // nothing there is "optional" in the sense this rewrite depends on — a
    // union found inside is walked for ITS properties, not collapsed itself.
    for key in [
        "$defs",
        "definitions",
        "patternProperties",
        "dependentSchemas",
    ] {
        if let Some(map) = obj.get_mut(key).and_then(Value::as_object_mut) {
            for child in map.values_mut() {
                walk(child, false, changed, false);
            }
        }
    }
    for key in ["oneOf", "anyOf", "allOf", "prefixItems"] {
        if let Some(list) = obj.get_mut(key).and_then(Value::as_array_mut) {
            for child in list.iter_mut() {
                walk(child, false, changed, false);
            }
        }
    }
    for key in ["items", "additionalProperties", "not", "if", "then", "else"] {
        // `additionalProperties: false` is a boolean, not a schema. `walk`
        // returns immediately on a non-object, so this needs no guard of its
        // own -- but the case is worth naming, because walking into it is the
        // obvious thing to write and finds nothing forever.
        if let Some(child) = obj.get_mut(key) {
            walk(child, false, changed, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{make_portable, portable_count};
    use serde_json::json;

    /// The common case, and 169 of the 172 findings: `Option<T>` becomes
    /// `["T","null"]`, and the property is already optional because it is not
    /// in `required`.
    #[test]
    fn an_optional_nullable_property_collapses_to_its_single_type() {
        let mut s = json!({
            "type": "object",
            "properties": { "filter": { "type": ["string", "null"] } }
        });
        assert_eq!(make_portable(&mut s), 1);
        assert_eq!(s["properties"]["filter"]["type"], json!("string"));
    }

    /// A REQUIRED nullable property must keep its union.
    ///
    /// The caller has to send the key, and `null` is the only way to send it
    /// empty. Collapsing here would advertise a schema that forbids a value
    /// the tool accepts, which is a different defect from the one being fixed.
    #[test]
    fn a_required_nullable_property_keeps_its_union() {
        let mut s = json!({
            "type": "object",
            "required": ["filter"],
            "properties": { "filter": { "type": ["string", "null"] } }
        });
        assert_eq!(make_portable(&mut s), 0);
        assert_eq!(s["properties"]["filter"]["type"], json!(["string", "null"]));
    }

    /// A union that is not about nullability is a real union and stays one.
    #[test]
    fn a_union_without_null_is_left_alone() {
        let mut s = json!({
            "type": "object",
            "properties": { "n": { "type": ["string", "integer"] } }
        });
        assert_eq!(make_portable(&mut s), 0);
        assert_eq!(s["properties"]["n"]["type"], json!(["string", "integer"]));
    }

    /// Three-way with null: there is no single type to collapse to, and
    /// picking one would silently drop the other.
    #[test]
    fn a_three_way_union_is_left_alone() {
        let mut s = json!({
            "type": "object",
            "properties": { "n": { "type": ["string", "integer", "null"] } }
        });
        assert_eq!(make_portable(&mut s), 0);
    }

    /// The walk reaches every place schemars puts a property.
    ///
    /// One fixture with all five shapes the strict run actually reported:
    /// top-level properties, a `$defs` type's properties, a `oneOf` branch's
    /// properties, an array's `items`, and `additionalProperties`.
    #[test]
    fn the_walk_reaches_defs_branches_items_and_additional_properties() {
        let mut s = json!({
            "type": "object",
            "properties": { "top": { "type": ["string", "null"] } },
            "$defs": {
                "Inner": {
                    "type": "object",
                    "properties": { "deep": { "type": ["integer", "null"] } },
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": { "branch": { "type": ["string", "null"] } }
                        }
                    ]
                }
            },
            "items": {
                "type": "object",
                "properties": { "each": { "type": ["number", "null"] } }
            },
            "additionalProperties": {
                "type": "object",
                "properties": { "extra": { "type": ["boolean", "null"] } }
            }
        });
        assert_eq!(make_portable(&mut s), 5);
        assert_eq!(s["properties"]["top"]["type"], json!("string"));
        assert_eq!(
            s["$defs"]["Inner"]["properties"]["deep"]["type"],
            json!("integer")
        );
        assert_eq!(
            s["$defs"]["Inner"]["oneOf"][0]["properties"]["branch"]["type"],
            json!("string")
        );
        assert_eq!(s["items"]["properties"]["each"]["type"], json!("number"));
        assert_eq!(
            s["additionalProperties"]["properties"]["extra"]["type"],
            json!("boolean")
        );
    }

    /// A schema with nothing to fix is returned byte-identical.
    #[test]
    fn a_schema_with_nothing_to_fix_is_unchanged() {
        let before = json!({
            "type": "object",
            "required": ["a"],
            "properties": { "a": { "type": "string" }, "b": { "type": "integer" } }
        });
        let mut after = before.clone();
        assert_eq!(make_portable(&mut after), 0);
        assert_eq!(before, after);
    }

    /// `additionalProperties: false` is a boolean, not a schema, and walking
    /// into it would be walking into nothing.
    #[test]
    fn a_boolean_additional_properties_is_not_walked_into() {
        let mut s = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "a": { "type": ["string", "null"] } }
        });
        assert_eq!(make_portable(&mut s), 1);
        assert_eq!(s["additionalProperties"], json!(false));
    }

    /// The counter counts without changing anything, so a gate can ask "how
    /// many would this fix" separately from fixing them.
    #[test]
    fn counting_does_not_modify() {
        let before = json!({
            "type": "object",
            "properties": { "a": { "type": ["string", "null"] } }
        });
        let mut probe = before.clone();
        assert_eq!(portable_count(&probe), 1);
        assert_eq!(probe, before, "counting must not rewrite");
        assert_eq!(make_portable(&mut probe), 1);
        assert_eq!(
            portable_count(&probe),
            0,
            "and a rewritten schema has none left"
        );
    }
}
