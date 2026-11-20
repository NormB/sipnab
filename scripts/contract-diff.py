#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Classify the changes between two versions of a sipnab output contract.

docs/stability.md states what sipnab promises about its machine-readable
surfaces. This script compares an OLD and a NEW snapshot of one surface and
says which changes break a program written against OLD:

    contract-diff.py --kind schema  OLD.json NEW.json   # a JSON Schema
    contract-diff.py --kind openapi OLD.json NEW.json   # an OpenAPI document

`schema` is for the report schemas in tests/schemas/; `openapi` is for
website/static/openapi.json, the REST API under /v1.

The rule, from a READER's side, since both surfaces are output:

- breaking: a property disappears or stops being required; a value can take a
  type the old schema did not allow (`null` included; no `type` allows every
  type); a closed enum gains a value or loses its list; a `const` changes; an
  operation, a response status or a parameter disappears; a parameter or a
  request body becomes required.
- additive: a new property, operation or optional parameter.

An enum that may grow without notice says so with `"x-sipnab-open-enum":
true` in both versions. Only local references (`#/...`) are followed; any
other reference is an error, because a part of the contract this script cannot
read is a part it cannot vouch for.

Prints one line per change, `breaking <path>: <what>` or `additive <path>:
<what>`, then a count. Exit 0: no breaking change. 1: at least one. 2: usage,
read or reference error; nothing was decided.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
ALL_TYPES = frozenset({"string", "number", "integer", "boolean", "object", "array", "null"})
OPEN_ENUM = "x-sipnab-open-enum"


class ContractError(Exception):
    """A snapshot this script cannot read as a contract."""


@dataclass(frozen=True)
class Change:
    kind: str  # "breaking" or "additive"
    path: str
    message: str


def _resolve(node, root, seen=()):
    """`node` with every top-level local `$ref` followed, and the refs followed."""
    refs = list(seen)
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#"):
            raise ContractError(f"reference {ref!r} is not local to the document")
        if ref in refs:
            return node, tuple(refs)
        refs.append(ref)
        target = root
        for part in ref[1:].split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or part not in target:
                raise ContractError(f"reference {ref!r} does not resolve")
            target = target[part]
        node = target
    return node, tuple(refs)


def _value_type(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    return "array" if isinstance(v, list) else "object"


def _types(s) -> frozenset:
    """The JSON types a value of schema `s` can have."""
    if s is True or not isinstance(s, dict):
        return ALL_TYPES
    t = s.get("type")
    if t is None:
        # Without `type`, a value list still limits the types to its values'.
        if "const" in s:
            return frozenset({_value_type(s["const"])})
        if "enum" in s:
            return frozenset(_value_type(v) for v in s["enum"])
        return ALL_TYPES
    ts = frozenset([t] if isinstance(t, str) else t)
    # Every integer is a number: a reader of `number` accepts an integer.
    return ts | ({"integer"} if "number" in ts else set())


def schema_changes(old, new, old_root=None, new_root=None, path="$", _seen=None) -> list[Change]:
    """Every change from `old` to `new`, read as an output schema."""
    old_root = old if old_root is None else old_root
    new_root = new if new_root is None else new_root
    seen = set() if _seen is None else _seen
    o, o_refs = _resolve(old, old_root)
    n, n_refs = _resolve(new, new_root)
    if o_refs or n_refs:
        # `seen` holds the reference pairs of this node's ancestors only (a new
        # set per branch), so a pair met again is a cycle and ends here, while
        # two sibling properties that use the same definition are both compared.
        pair = (o_refs[-1:], n_refs[-1:])
        if pair in seen:
            return []
        seen = seen | {pair}
    out: list[Change] = []

    added = sorted(_types(n) - _types(o))
    if added:
        out.append(Change("breaking", path, f"may now be of type {', '.join(added)}"))

    if isinstance(o, dict) and isinstance(n, dict):
        if "const" in o and n.get("const", object()) != o["const"]:
            out.append(Change("breaking", path, f"const {o['const']!r} changed"))
        if "enum" in o:
            if "enum" not in n:
                out.append(Change("breaking", path, "enum list removed"))
            else:
                grown = [v for v in n["enum"] if v not in o["enum"]]
                if grown and not (o.get(OPEN_ENUM) is True and n.get(OPEN_ENUM) is True):
                    out.append(Change("breaking", path, f"closed enum gained {grown!r}"))

        o_props = o.get("properties") or {}
        n_props = n.get("properties") or {}
        o_req = set(o.get("required") or [])
        n_req = set(n.get("required") or [])
        for name in sorted(set(o_props) | set(n_props)):
            sub = f"{path}.{name}"
            if name not in n_props:
                out.append(Change("breaking", sub, "property removed"))
                continue
            if name not in o_props:
                out.append(Change("additive", sub, "property added"))
                continue
            if name in o_req and name not in n_req:
                out.append(Change("breaking", sub, "no longer required, so it may be absent"))
            out.extend(schema_changes(o_props[name], n_props[name], old_root, new_root, sub, seen))

        if "items" in o and "items" in n:
            out.extend(schema_changes(o["items"], n["items"], old_root, new_root, f"{path}[]", seen))
    return out


def _params(item: dict, operation: dict) -> dict:
    """The operation's parameters, path-level ones included, keyed (in, name)."""
    out = {}
    for p in list(item.get("parameters") or []) + list(operation.get("parameters") or []):
        out[(p.get("in"), p.get("name"))] = p.get("in") == "path" or bool(p.get("required"))
    return out


def _json_schema(response: dict):
    return ((response.get("content") or {}).get("application/json") or {}).get("schema")


def openapi_changes(old: dict, new: dict) -> list[Change]:
    """Every change from `old` to `new`, read as the API a client calls."""
    for d in (old, new):
        if not isinstance(d, dict) or not isinstance(d.get("paths"), dict):
            raise ContractError("an OpenAPI document has no `paths` object")
    out: list[Change] = []

    def ops(d):
        return {(m.upper(), p): (item, item[m]) for p, item in d["paths"].items() for m in METHODS if m in item}

    o_ops, n_ops = ops(old), ops(new)
    for key in sorted(set(o_ops) | set(n_ops), key=lambda k: (k[1], k[0])):
        where = f"{key[0]} {key[1]}"
        if key not in n_ops:
            out.append(Change("breaking", where, "operation removed"))
            continue
        if key not in o_ops:
            out.append(Change("additive", where, "operation added"))
            continue
        (o_item, o_op), (n_item, n_op) = o_ops[key], n_ops[key]
        o_par, n_par = _params(o_item, o_op), _params(n_item, n_op)
        for pk in sorted(set(o_par) | set(n_par), key=lambda k: (str(k[0]), str(k[1]))):
            pwhere = f"{where} {pk[0]} {pk[1]}"
            if pk not in n_par:
                out.append(Change("breaking", pwhere, "parameter removed"))
            elif pk not in o_par:
                kind = "breaking" if n_par[pk] else "additive"
                out.append(Change(kind, pwhere, "required parameter added" if n_par[pk] else "parameter added"))
            elif n_par[pk] and not o_par[pk]:
                out.append(Change("breaking", pwhere, "parameter became required"))
        if (n_op.get("requestBody") or {}).get("required") and not (o_op.get("requestBody") or {}).get("required"):
            out.append(Change("breaking", where, "request body became required"))
        o_res, n_res = o_op.get("responses") or {}, n_op.get("responses") or {}
        for status in sorted(o_res):
            if status not in n_res:
                out.append(Change("breaking", f"{where} {status}", "response removed"))
                continue
            o_s, n_s = _json_schema(o_res[status]), _json_schema(n_res[status])
            if o_s is not None and n_s is not None:
                out.extend(schema_changes(o_s, n_s, old, new, f"{where} {status} $"))
            elif o_s is not None:
                out.append(Change("breaking", f"{where} {status}", "JSON body removed"))
        for status in sorted(set(n_res) - set(o_res)):
            out.append(Change("additive", f"{where} {status}", "response added"))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[0] != "--kind" or argv[1] not in ("schema", "openapi"):
        print("usage: contract-diff.py --kind schema|openapi OLD.json NEW.json", file=sys.stderr)
        return 2
    try:
        docs = []
        for path in argv[2:]:
            with open(path, encoding="utf-8") as f:
                docs.append(json.load(f))
        diff = schema_changes if argv[1] == "schema" else openapi_changes
        changes = diff(*docs)
    except (OSError, ValueError, ContractError) as e:
        print(f"contract-diff: {e}; nothing was decided", file=sys.stderr)
        return 2
    for c in changes:
        print(f"{c.kind} {c.path}: {c.message}")
    n = sum(c.kind == "breaking" for c in changes)
    print(f"contract-diff: {len(changes)} change(s), {n} breaking")
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
