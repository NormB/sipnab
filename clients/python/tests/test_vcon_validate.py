"""Validating a vCon against the working group's own schema file.

jsonschema checks a `format` only when a checker for it is installed, and the
three formats the vCon schema uses (`uuid`, `date-time` and `uri`) have none
in a plain install: `created_at: "yesterday"` validates. These tests pin the
checks the program supplies itself, and its refusal of a schema whose formats
it cannot check.
"""

import importlib.util
import json
import pathlib
import sys

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vv = _load("vcon_validate")

UUID = "018bcfe5-6800-8626-9e41-346b98451fa5"
WHEN = "2026-09-24T19:29:05.197749022+00:00"


def container(**extra) -> dict:
    return {"vcon": "0.4.0", "uuid": UUID, "created_at": WHEN, **extra}


def publisher() -> dict:
    return json.loads(vv.DEFAULT_SCHEMA.read_text())


def test_the_default_schema_is_the_publishers_file():
    assert vv.DEFAULT_SCHEMA == CLIENTS.parent.parent / "tests/schemas/publisher/vcon_json_schema.json"
    assert publisher()["$id"] == "https://ietf.org/vcon/schemas/unsigned-vcon.json"


def test_a_container_the_schema_admits_has_no_errors():
    assert vv.errors(container(), publisher()) == []


@pytest.mark.parametrize(
    "field, value",
    [("created_at", "yesterday"), ("created_at", "2026-09-24"), ("uuid", "not-a-uuid")],
)
def test_a_malformed_format_is_an_error(field, value):
    found = vv.errors(container(**{field: value}), publisher())
    assert [(path, "is not a '" in why) for path, why in found] == [(f"/{field}", True)], found


def test_a_relative_uri_is_an_error():
    found = vv.errors(container(amended={"url": "vcons/1", "content_hash": "sha512-x"}), publisher())
    assert [path for path, _ in found] == ["/amended/url"], found


def test_a_dialog_with_no_type_is_refused_by_the_publishers_schema():
    # sipnab's own copy drops `type` from `required`, its one documented
    # deviation; the publisher's file does not, and this is what a store
    # validating against that file says about a signaling-only container.
    found = vv.errors(container(dialog=[{"start": WHEN}]), publisher())
    assert found == [("/dialog/0", "'type' is a required property")], found


def test_a_schema_using_a_format_the_program_cannot_check_is_refused():
    schema = {"type": "object", "properties": {"host": {"type": "string", "format": "hostname"}}}
    with pytest.raises(vv.UncheckableFormat, match="hostname"):
        vv.errors({"host": "x"}, schema)
