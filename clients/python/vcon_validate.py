#!/usr/bin/env python3
"""Validate vCon containers against the vCon working group's own JSON Schema.

A store that refuses a container tells whoever posted it, not whoever built
it, so check before you send. By default this reads the working group's
schema file exactly as its publisher committed it,
tests/schemas/publisher/vcon_json_schema.json (ietf-wg-vcon/
draft-ietf-vcon-vcon-core at 265e0449, 2026-06-30), not sipnab's copy: sipnab's
copy drops `type` from the Dialog Object's `required` list, and a store
validating against the publisher's file does not. Pass --schema to check
against another file.

The engine is jsonschema, not sipnab. sipnab's own `validate_vcon` answers
with a validator sipnab wrote; this answers with one it did not.

jsonschema checks a `format` only when it has a checker for it, and a plain
install has none for `uuid`, `date-time` or `uri`, the three the vCon schema
uses, so `created_at: "yesterday"` would pass. This program brings its own
checker for each, and refuses a schema that uses a format it cannot check
rather than passing whatever that format was meant to catch.

Exit status: 0 when every container is valid, 1 when any is not, 2 when a
file cannot be read or is not JSON.
"""

import argparse
import datetime
import json
import pathlib
import re
import sys
import uuid

from jsonschema import Draft7Validator, FormatChecker

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_SCHEMA = HERE.parent.parent / "tests" / "schemas" / "publisher" / "vcon_json_schema.json"

# RFC 3339 section 5.6: a full date, "T", a time with an optional fraction,
# and a zone. JSON Schema's `date-time` is exactly this production.
DATE_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
# RFC 3986 section 3: an absolute URI starts with a scheme and a colon.
URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]*$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class UncheckableFormat(Exception):
    """The schema names a `format` this program has no checker for."""


def _date_time(value) -> bool:
    if not isinstance(value, str):
        return True  # `format` constrains strings only; `type` covers the rest
    m = DATE_TIME.match(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    try:
        # A leap second (:60) is legal in RFC 3339 and unknown to datetime.
        datetime.datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return False
    return second <= 60


def _uuid(value) -> bool:
    if not isinstance(value, str):
        return True
    if not UUID.match(value):
        return False
    uuid.UUID(value)
    return True


def _uri(value) -> bool:
    return not isinstance(value, str) or bool(URI.match(value))


CHECKERS = {"date-time": _date_time, "uuid": _uuid, "uri": _uri}


def formats_in(node) -> set[str]:
    """Every `format` value anywhere in a schema."""
    found = set()
    if isinstance(node, dict):
        if isinstance(node.get("format"), str):
            found.add(node["format"])
        for child in node.values():
            found |= formats_in(child)
    elif isinstance(node, list):
        for child in node:
            found |= formats_in(child)
    return found


def errors(container, schema: dict) -> list[tuple[str, str]]:
    """Every way `container` breaks `schema`, as (JSON Pointer, message)."""
    # snippet:start vcon-validate
    unknown = formats_in(schema) - CHECKERS.keys()
    if unknown:
        raise UncheckableFormat(
            f"the schema uses format(s) {sorted(unknown)} that nothing here checks"
        )
    checker = FormatChecker(formats=())
    for name, check in CHECKERS.items():
        checker.checks(name)(check)
    validator = Draft7Validator(schema, format_checker=checker)
    return sorted(
        ("/" + "/".join(str(p) for p in e.absolute_path), e.message)
        for e in validator.iter_errors(container)
    )
    # snippet:end vcon-validate


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("containers", nargs="+", type=pathlib.Path, help="vCon JSON files")
    ap.add_argument("--schema", type=pathlib.Path, default=DEFAULT_SCHEMA)
    args = ap.parse_args()

    try:
        schema = json.loads(args.schema.read_text())
    except (OSError, ValueError) as e:
        print(f"{args.schema}: {e}", file=sys.stderr)
        return 2
    print(f"checked against {schema.get('$id', '(no $id)')} ({args.schema})")

    status = 0
    for path in args.containers:
        try:
            container = json.loads(path.read_text())
        except (OSError, ValueError) as e:
            print(f"{path}: {e}", file=sys.stderr)
            return 2
        found = errors(container, schema)
        print(f"{'invalid' if found else 'valid':<8} {path}")
        for pointer, message in found:
            print(f"  {pointer}: {message}")
        if found:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
