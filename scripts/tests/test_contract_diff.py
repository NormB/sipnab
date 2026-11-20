# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/contract-diff.py tells a breaking change from an additive one.

docs/stability.md states the rule this file holds. sipnab's JSON reports and
REST answers are OUTPUT: what a program reading them relies on. So a change is
breaking when a reader that worked against the old shape can fail against the
new one:

- a property disappears, or stops being required (it may now be absent);
- a value can have a type the old shape did not allow (`null` included);
- an enum gains a value, unless the schema marks it `"x-sipnab-open-enum":
  true`, or a `const` changes;
- an API operation, a response status or a parameter disappears, or a
  request gains a required parameter or a required body.

Additions a reader can ignore (a new optional property, a new operation, a new
optional parameter) are additive.
"""

import json

import pytest
from conftest import load

cd = load("contract-diff")


def kinds(changes):
    return sorted({c.kind for c in changes})


def breaking(changes):
    return [c for c in changes if c.kind == "breaking"]


def obj(props, required=(), **extra):
    return {"type": "object", "properties": props, "required": list(required), **extra}


S = {"type": "string"}
I = {"type": "integer"}


# ------------------------------------------------------------ schema: success


def test_success_identical_schemas_have_no_change():
    s = obj({"a": S}, ["a"])
    assert cd.schema_changes(s, s) == []


def test_success_a_new_optional_property_is_additive():
    ch = cd.schema_changes(obj({"a": S}), obj({"a": S, "b": I}))
    assert kinds(ch) == ["additive"] and ch[0].path == "$.b", ch


def test_success_a_new_required_property_is_additive():
    ch = cd.schema_changes(obj({"a": S}), obj({"a": S, "b": I}, ["b"]))
    assert not breaking(ch), ch


def test_success_an_optional_property_made_required_is_not_breaking():
    ch = cd.schema_changes(obj({"a": S}), obj({"a": S}, ["a"]))
    assert not breaking(ch), ch


def test_success_narrowing_a_type_is_not_breaking():
    ch = cd.schema_changes({"type": ["string", "null"]}, {"type": "string"})
    assert not breaking(ch), ch


def test_success_removing_an_enum_value_is_not_breaking():
    ch = cd.schema_changes({"enum": ["a", "b"]}, {"enum": ["a"]})
    assert not breaking(ch), ch


def test_success_an_open_enum_may_gain_a_value():
    old = {"enum": ["a"], "x-sipnab-open-enum": True}
    new = {"enum": ["a", "b"], "x-sipnab-open-enum": True}
    assert not breaking(cd.schema_changes(old, new))


def test_success_a_description_change_is_no_change():
    ch = cd.schema_changes({"type": "string", "description": "x"}, {"type": "string", "description": "y"})
    assert ch == [], ch


def test_success_refs_resolve_on_both_sides():
    old = {"$defs": {"T": S}, "type": "object", "properties": {"a": {"$ref": "#/$defs/T"}}}
    new = {"$defs": {"U": S}, "type": "object", "properties": {"a": {"$ref": "#/$defs/U"}}}
    assert cd.schema_changes(old, new) == []


def test_success_array_items_with_a_new_optional_property_are_additive():
    old = {"type": "array", "items": obj({"a": S})}
    new = {"type": "array", "items": obj({"a": S, "b": S})}
    ch = cd.schema_changes(old, new)
    assert kinds(ch) == ["additive"] and ch[0].path == "$[].b", ch


def test_success_the_real_report_schemas_are_unchanged_against_themselves():
    import pathlib

    for f in sorted((pathlib.Path(__file__).resolve().parents[2] / "tests/schemas").glob("*.schema.json")):
        s = json.loads(f.read_text())
        assert cd.schema_changes(s, s) == [], f.name


def test_success_main_exits_0_when_only_additive(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(obj({"a": S})))
    b.write_text(json.dumps(obj({"a": S, "b": S})))
    assert cd.main(["--kind", "schema", str(a), str(b)]) == 0
    assert "additive $.b" in capsys.readouterr().out


# ------------------------------------------------------------ schema: failure


def test_failure_a_removed_property_is_breaking():
    ch = cd.schema_changes(obj({"a": S, "b": S}), obj({"a": S}))
    assert [(c.kind, c.path) for c in ch] == [("breaking", "$.b")], ch


def test_failure_a_required_property_made_optional_is_breaking():
    ch = cd.schema_changes(obj({"a": S}, ["a"]), obj({"a": S}))
    assert [c.path for c in breaking(ch)] == ["$.a"], ch


def test_failure_a_changed_type_is_breaking():
    ch = cd.schema_changes(obj({"a": S}), obj({"a": I}))
    assert [c.path for c in breaking(ch)] == ["$.a"], ch


def test_failure_allowing_null_is_breaking():
    ch = cd.schema_changes({"type": "string"}, {"type": ["string", "null"]})
    assert breaking(ch), ch


def test_failure_a_closed_enum_gaining_a_value_is_breaking():
    ch = cd.schema_changes({"enum": ["a"]}, {"enum": ["a", "b"]})
    assert breaking(ch) and "b" in breaking(ch)[0].message, ch


def test_failure_a_changed_const_is_breaking():
    assert breaking(cd.schema_changes({"const": 1}, {"const": 2}))


def test_failure_a_removed_nested_property_names_its_path():
    old = obj({"t": obj({"x": I, "y": I})})
    new = obj({"t": obj({"x": I})})
    assert [c.path for c in breaking(cd.schema_changes(old, new))] == ["$.t.y"]


def test_failure_a_change_behind_a_ref_is_found():
    old = {"$defs": {"T": obj({"x": I})}, **obj({"a": {"$ref": "#/$defs/T"}})}
    new = {"$defs": {"T": obj({"x": S})}, **obj({"a": {"$ref": "#/$defs/T"}})}
    assert [c.path for c in breaking(cd.schema_changes(old, new))] == ["$.a.x"]


def test_failure_a_changed_item_type_is_breaking():
    old = {"type": "array", "items": I}
    new = {"type": "array", "items": S}
    assert [c.path for c in breaking(cd.schema_changes(old, new))] == ["$[]"]


def test_failure_an_open_enum_made_closed_and_grown_is_breaking():
    old = {"enum": ["a"], "x-sipnab-open-enum": True}
    new = {"enum": ["a", "b"]}
    assert breaking(cd.schema_changes(old, new))


def test_failure_main_exits_1_on_a_breaking_change(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(obj({"a": S})))
    b.write_text(json.dumps(obj({})))
    assert cd.main(["--kind", "schema", str(a), str(b)]) == 1
    assert "breaking $.a" in capsys.readouterr().out


def test_failure_gaining_a_type_through_a_removed_type_key_is_breaking():
    # No `type` means any type: a reader of the old string can get anything.
    assert breaking(cd.schema_changes({"type": "string"}, {}))


# --------------------------------------------------------------- schema: edge


def test_edge_a_ref_cycle_ends():
    s = {"$defs": {"N": obj({"next": {"$ref": "#/$defs/N"}})}, "$ref": "#/$defs/N"}
    assert cd.schema_changes(s, s) == []


def test_edge_an_unresolvable_ref_is_an_error():
    with pytest.raises(cd.ContractError):
        cd.schema_changes({"$ref": "#/$defs/Missing"}, {"type": "string"})


def test_edge_narrowing_to_an_untyped_enum_is_not_breaking():
    # The enum's values limit the types: a reader of string-or-integer reads "a".
    assert not breaking(cd.schema_changes({"type": ["string", "integer"]}, {"enum": ["a"]}))


def test_edge_an_untyped_enum_with_a_new_value_type_is_breaking():
    assert breaking(cd.schema_changes({"type": "string"}, {"enum": ["a", None]}))


def test_edge_an_untyped_const_takes_the_type_of_its_value():
    assert not breaking(cd.schema_changes({"type": "string"}, {"const": "a"}))


def test_edge_adding_the_type_of_a_const_is_no_change():
    assert cd.schema_changes({"const": 1}, {"type": "integer", "const": 1}) == []


def test_edge_a_remote_ref_is_an_error():
    with pytest.raises(cd.ContractError, match="not local"):
        cd.schema_changes({"$ref": "https://example.com/x.json"}, {"type": "string"})


def test_edge_a_ref_with_an_escaped_pointer_resolves():
    s = {"$defs": {"a/b": S}, "$ref": "#/$defs/a~1b"}
    assert cd.schema_changes(s, s) == []


def test_edge_type_lists_compare_as_sets():
    assert cd.schema_changes({"type": ["null", "string"]}, {"type": ["string", "null"]}) == []


def test_edge_integer_to_number_is_breaking_for_a_reader():
    assert breaking(cd.schema_changes({"type": "integer"}, {"type": "number"}))


def test_edge_number_to_integer_is_not_breaking():
    assert not breaking(cd.schema_changes({"type": "number"}, {"type": "integer"}))


def test_edge_an_enum_removed_entirely_is_breaking():
    assert breaking(cd.schema_changes({"type": "string", "enum": ["a"]}, {"type": "string"}))


def test_edge_an_enum_added_where_there_was_none_is_not_breaking():
    assert not breaking(cd.schema_changes({"type": "string"}, {"type": "string", "enum": ["a"]}))


def test_edge_a_property_schema_that_is_true_is_any():
    assert cd.schema_changes(obj({"a": True}), obj({"a": True})) == []


def test_edge_changes_come_in_a_stable_order():
    old = obj({"b": S, "a": S})
    new = obj({})
    assert [c.path for c in cd.schema_changes(old, new)] == ["$.a", "$.b"]


def test_edge_main_with_a_missing_file_is_an_error(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("{}")
    assert cd.main(["--kind", "schema", str(a), str(tmp_path / "absent.json")]) == 2


def test_edge_main_with_malformed_json_is_an_error(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text("{}")
    b.write_text("{")
    assert cd.main(["--kind", "schema", str(a), str(b)]) == 2


def test_edge_main_with_an_unknown_kind_is_a_usage_error(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("{}")
    assert cd.main(["--kind", "yaml", str(a), str(a)]) == 2


def test_edge_main_with_too_few_arguments_is_a_usage_error():
    assert cd.main(["--kind", "schema"]) == 2


# ----------------------------------------------------------------- OpenAPI


def op(params=(), responses=None, body=None):
    o = {"parameters": list(params), "responses": responses or {"200": {"description": "ok"}}}
    if body is not None:
        o["requestBody"] = body
    return o


def api(paths, schemas=None):
    return {"openapi": "3.1.0", "paths": paths, "components": {"schemas": schemas or {}}}


def param(name, where="query", required=False):
    return {"name": name, "in": where, "required": required, "schema": S}


def json_response(schema):
    return {"200": {"description": "ok", "content": {"application/json": {"schema": schema}}}}


def test_success_identical_documents_have_no_change():
    d = api({"/v1/x": {"get": op([param("q")])}})
    assert cd.openapi_changes(d, d) == []


def test_success_a_new_operation_is_additive():
    old = api({"/v1/x": {"get": op()}})
    new = api({"/v1/x": {"get": op(), "post": op()}, "/v1/y": {"get": op()}})
    ch = cd.openapi_changes(old, new)
    assert kinds(ch) == ["additive"] and len(ch) == 2, ch


def test_success_a_new_optional_parameter_is_additive():
    old = api({"/v1/x": {"get": op()}})
    new = api({"/v1/x": {"get": op([param("q")])}})
    assert kinds(cd.openapi_changes(old, new)) == ["additive"]


def test_success_a_required_parameter_made_optional_is_not_breaking():
    old = api({"/v1/x": {"get": op([param("q", required=True)])}})
    new = api({"/v1/x": {"get": op([param("q")])}})
    assert not breaking(cd.openapi_changes(old, new))


def test_success_a_new_optional_response_property_is_additive():
    old = api({"/v1/x": {"get": op(responses=json_response(obj({"a": S})))}})
    new = api({"/v1/x": {"get": op(responses=json_response(obj({"a": S, "b": S})))}})
    assert kinds(cd.openapi_changes(old, new)) == ["additive"]


def test_success_the_published_document_is_unchanged_against_itself():
    import pathlib

    d = json.loads((pathlib.Path(__file__).resolve().parents[2] / "website/static/openapi.json").read_text())
    assert cd.openapi_changes(d, d) == []


def test_success_main_reads_openapi(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps(api({"/v1/x": {"get": op()}})))
    assert cd.main(["--kind", "openapi", str(a), str(a)]) == 0


def test_failure_a_removed_operation_is_breaking():
    old = api({"/v1/x": {"get": op(), "delete": op()}})
    new = api({"/v1/x": {"get": op()}})
    assert [c.path for c in breaking(cd.openapi_changes(old, new))] == ["DELETE /v1/x"]


def test_failure_a_removed_path_is_breaking():
    old = api({"/v1/x": {"get": op()}, "/v1/y": {"get": op()}})
    new = api({"/v1/x": {"get": op()}})
    assert [c.path for c in breaking(cd.openapi_changes(old, new))] == ["GET /v1/y"]


def test_failure_a_new_required_parameter_is_breaking():
    old = api({"/v1/x": {"get": op()}})
    new = api({"/v1/x": {"get": op([param("q", required=True)])}})
    assert breaking(cd.openapi_changes(old, new))


def test_failure_an_optional_parameter_made_required_is_breaking():
    old = api({"/v1/x": {"get": op([param("q")])}})
    new = api({"/v1/x": {"get": op([param("q", required=True)])}})
    assert breaking(cd.openapi_changes(old, new))


def test_failure_a_removed_parameter_is_breaking():
    old = api({"/v1/x": {"get": op([param("q")])}})
    new = api({"/v1/x": {"get": op()}})
    assert [c.path for c in breaking(cd.openapi_changes(old, new))] == ["GET /v1/x query q"]


def test_failure_a_removed_response_status_is_breaking():
    old = api({"/v1/x": {"get": op(responses={"200": {"description": "ok"}, "404": {"description": "no"}})}})
    new = api({"/v1/x": {"get": op()}})
    assert [c.path for c in breaking(cd.openapi_changes(old, new))] == ["GET /v1/x 404"]


def test_failure_a_removed_response_property_is_breaking_through_components():
    ref = {"$ref": "#/components/schemas/T"}
    old = api({"/v1/x": {"get": op(responses=json_response(ref))}}, {"T": obj({"a": S, "b": S})})
    new = api({"/v1/x": {"get": op(responses=json_response(ref))}}, {"T": obj({"a": S})})
    assert [c.path for c in breaking(cd.openapi_changes(old, new))] == ["GET /v1/x 200 $.b"]


def test_failure_a_newly_required_request_body_is_breaking():
    old = api({"/v1/x": {"post": op()}})
    new = api({"/v1/x": {"post": op(body={"required": True, "content": {}})}})
    assert breaking(cd.openapi_changes(old, new))


def test_failure_main_exits_1_on_a_removed_operation(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(api({"/v1/x": {"get": op()}})))
    b.write_text(json.dumps(api({})))
    assert cd.main(["--kind", "openapi", str(a), str(b)]) == 1


def test_edge_a_parameter_is_keyed_by_name_and_location():
    old = api({"/v1/x": {"get": op([param("id", "query")])}})
    new = api({"/v1/x": {"get": op([param("id", "header")])}})
    assert breaking(cd.openapi_changes(old, new))


def test_edge_path_level_parameters_apply_to_every_operation():
    old = api({"/v1/x/{id}": {"parameters": [param("id", "path", True)], "get": op()}})
    new = api({"/v1/x/{id}": {"get": op([param("id", "path", True)])}})
    assert cd.openapi_changes(old, new) == []


def test_edge_a_path_parameter_counts_as_required_even_unmarked():
    old = api({"/v1/x": {"get": op()}})
    new = api({"/v1/x": {"get": op([{"name": "id", "in": "path", "schema": S}])}})
    assert breaking(cd.openapi_changes(old, new))


def test_edge_non_method_keys_of_a_path_item_are_not_operations():
    old = api({"/v1/x": {"summary": "s", "get": op()}})
    new = api({"/v1/x": {"get": op()}})
    assert cd.openapi_changes(old, new) == []


def test_edge_a_response_without_json_content_compares_status_only():
    old = api({"/v1/x": {"get": op(responses={"204": {"description": "none"}})}})
    assert cd.openapi_changes(old, old) == []


def test_edge_a_document_without_paths_is_an_error():
    with pytest.raises(cd.ContractError):
        cd.openapi_changes({"openapi": "3.1.0"}, api({}))
