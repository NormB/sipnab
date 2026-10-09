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
    # core-04 section 4.3.1: every Dialog Object names its type. sipnab wrote
    # this shape for a signaling-only call under core-03; core-04 refuses it.
    found = vv.errors(container(dialog=[{"start": WHEN}]), publisher())
    assert found == [("/dialog/0", "'type' is a required property")], found


def test_a_schema_using_a_format_the_program_cannot_check_is_refused():
    schema = {"type": "object", "properties": {"host": {"type": "string", "format": "hostname"}}}
    with pytest.raises(vv.UncheckableFormat, match="hostname"):
        vv.errors({"host": "x"}, schema)


# Appendix A.4 of draft-ietf-vcon-vcon-core-04, verbatim from
# examples/ab_call_ext_rec.vcon at the draft-ietf-vcon-vcon-core-04 tag.
CORE_04_A4 = {
    "created_at": "2022-06-21T13:53:00-04:00",
    "parties": [{"tel": "+12345678901", "name": "Alice"}, {"tel": "+19876543210", "name": "Bob"}],
    "dialog": [
        {
            "type": "recording",
            "start": "2022-06-21T17:53:26.000+00:00",
            "duration": 33.12,
            "parties": [0, 1],
            "url": "https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core/raw/refs/heads/main/examples/ab_call.mp3",
            "mediatype": "audio/x-mp3",
            "filename": "ab_call.mp3",
            "content_hash": "sha512-GLy6IPaIUM1GqzZqfIPZlWjaDsNgNvZM0iCONNThnH0a75fhUM6cYzLZ5GynSURREvZwmOh54-2lRRieyj82UQ",
        }
    ],
    "analysis": [],
    "attachments": [],
    "uuid": "01a07da8-c2bb-83e5-b9a2-279e0d16bc46",
}


def test_the_core_04_example_a4_is_valid():
    assert vv.errors(CORE_04_A4, publisher()) == []


def test_a_core_04_placeholder_dialog_object_is_valid():
    # core-04 section 4.3: a placeholder "contains only the type parameter";
    # section 4.3.2 makes start a SHOULD. The core-03 schema required start.
    assert vv.errors(container(dialog=[{"type": "recording"}]), publisher()) == []


@pytest.mark.parametrize(
    "label, extra, pointer, needle",
    [
        # core-04 section 4.3.4: parties MUST NOT be present on transfer.
        ("transfer with parties", {"dialog": [{"type": "transfer", "parties": [0]}]}, "/dialog/0", "should not be valid"),
        # core-04 section 4.3.14: one UnsignedInt, no array form.
        ("transfer_target array", {"dialog": [{"type": "transfer", "transfer_target": [1, 2]}]}, "/dialog/0/transfer_target", "is not of type 'integer'"),
        # core-04 section 4.3.11: incomplete MUST carry a disposition.
        ("incomplete, no disposition", {"dialog": [{"type": "incomplete"}]}, "/dialog/0", "'disposition' is a required property"),
        # core-04 Table 1 note (3): a non-empty body needs its encoding.
        ("body, no encoding", {"dialog": [{"type": "text", "mediatype": "text/plain", "body": "hi"}]}, "/dialog/0", "'encoding' is a required property"),
        # core-04 section 4.3.13.1: keydown needs a button.
        ("keydown, no button", {"dialog": [{"type": "recording", "party_history": [{"party": 0, "time": WHEN, "event": "keydown"}]}]}, "/dialog/0/party_history/0", "'button' is a required property"),
        # core-04 section 4.1.8: redacted and amended are mutually exclusive.
        ("redacted and amended", {"redacted": {"type": "pii"}, "amended": {"uuid": UUID}}, "/", "should not be valid"),
    ],
)
def test_each_rule_core_04_added_is_enforced(label, extra, pointer, needle):
    found = vv.errors(container(**extra), publisher())
    assert any(path == pointer and needle in why for path, why in found), (label, found)
