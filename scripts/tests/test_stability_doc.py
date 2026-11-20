# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""docs/stability.md says what scripts/contract-diff.py does, and this file
holds each statement to the script.

- Every rule the page lists (a breaking change, an additive change, a change
  the script does not compare) has a probe here, and every probe's rule is on
  the page, word for word. A probe is the smallest pair of snapshots the rule
  speaks of; the script must classify it as the page says.
- The page's examples are run: the `git show` lines of each example read the
  named release tags of this clone, and the script's output must be the
  page's `text` block, byte for byte.
- Each message the page's troubleshooting quotes is one the script (or git)
  prints for the cause the page gives, and each such cause is on the page.
- The surfaces table names openapi.json and every report schema sipnab owns
  (a `$id` under https://sipnab.com/), and no other file.

The examples need the release tags (`git fetch --tags`): CI's checkout
fetches them, and a clone without them fails here with that advice rather
than passing without a check.
"""

import json
import pathlib
import re
import shlex
import subprocess
import sys

import pytest
from conftest import load

cd = load("contract-diff")

REPO = pathlib.Path(__file__).resolve().parents[2]
PAGE = REPO / "docs" / "stability.md"
SCRIPT = REPO / "scripts" / "contract-diff.py"


# ------------------------------------------------------------------ the page


def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _is_fence(line: str) -> bool:
    return line.lstrip().startswith("```")


def section(title: str) -> list[str]:
    """The lines under the heading `title` (any level), up to the next heading
    of the same or a higher level. A `#` line inside a fence is no heading."""
    lines = page().splitlines()
    inside = False
    start = level = None
    for at, line in enumerate(lines):
        if _is_fence(line):
            inside = not inside
            continue
        if inside:
            continue
        m = re.match(r"^(#{1,6}) (.*)$", line)
        if not m:
            continue
        if start is not None and len(m.group(1)) <= level:
            return lines[start:at]
        if start is None and m.group(2).strip() == title:
            start, level = at + 1, len(m.group(1))
    if start is None:
        raise AssertionError(f"docs/stability.md has no heading {title!r}")
    return lines[start:]


def fences(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Each fenced block of `lines` as (info string, body lines)."""
    out, body, info = [], None, ""
    for line in lines:
        if _is_fence(line):
            if body is None:
                info, body = line.strip()[3:].strip(), []
            else:
                out.append((info, body))
                body = None
        elif body is not None:
            body.append(line)
    return out


def bullets_after(lines: list[str], intro: str) -> list[str]:
    """The `- ` items of the list that follows the line ending in `intro`,
    each with its continuation lines joined and its closing `;`, `.`, `; and`
    or `; or` dropped."""
    at = next((i for i, line in enumerate(lines) if line.strip().endswith(intro)), None)
    if at is None:
        raise AssertionError(f"no line ending {intro!r} in that section")
    items: list[str] = []
    for line in lines[at + 1 :]:
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif items and line.startswith("  ") and line.strip():
            items[-1] += " " + line.strip()
        elif not line.strip() and not items:
            continue
        else:
            break
    return [re.sub(r"(; (and|or)|;|\.)$", "", item) for item in items]


def code_spans(text: str) -> list[str]:
    """The inline code spans of `text`, double-backtick spans included."""
    return [m.group(2).strip() for m in re.finditer(r"(`+)(.+?)\1", text)]


# ---------------------------------------------------------------- the probes


def obj(props, required=(), **extra):
    return {"type": "object", "properties": props, "required": list(required), **extra}


S = {"type": "string"}
I = {"type": "integer"}
N = {"type": "number"}


def api(op=None, path="/v1/x", method="get", **path_level):
    """An OpenAPI document with one operation (none when `op` is None)."""
    item = dict(path_level)
    if op is not None:
        item[method] = op
    return {"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {path: item} if item else {}}


def answer(schema, status="200", media="application/json"):
    return {"responses": {status: {"description": "ok", "content": {media: {"schema": schema}}}}}


def q(name, required=False, schema=None):
    p = {"in": "query", "name": name, "required": required}
    if schema is not None:
        p["schema"] = schema
    return p


# (section heading, list intro) -> {rule text on the page: (diff function, old, new)}
BODY = "A report or a response body"
OPS = "The REST API operations"
NOT = "What the script does not compare"

BREAKING = {
    (BODY, "breaking when:"): {
        "a property disappears": (cd.schema_changes, obj({"a": S}), obj({})),
        "a required property becomes optional, so it may be absent": (
            cd.schema_changes,
            obj({"a": S}, ["a"]),
            obj({"a": S}),
        ),
        "a value may take a type the older release never sent, `null` included": (
            cd.schema_changes,
            S,
            {"type": ["string", "null"]},
        ),
        "a schema drops its `type`, so the value may be of any type": (cd.schema_changes, S, {}),
        "a closed list of values (`enum`) gains a value": (
            cd.schema_changes,
            {"type": "string", "enum": ["a"]},
            {"type": "string", "enum": ["a", "b"]},
        ),
        "a closed list of values loses its list": (
            cd.schema_changes,
            {"type": "string", "enum": ["a"]},
            S,
        ),
        "a fixed value (`const`) changes": (
            cd.schema_changes,
            {"type": "string", "const": "a"},
            {"type": "string", "const": "b"},
        ),
    },
    (OPS, "breaking when:"): {
        "an operation, a method on a path, disappears": (cd.openapi_changes, api(answer(S)), api()),
        "a parameter disappears": (
            cd.openapi_changes,
            api({"parameters": [q("a")], **answer(S)}),
            api(answer(S)),
        ),
        "a new required parameter appears": (
            cd.openapi_changes,
            api(answer(S)),
            api({"parameters": [q("a", True)], **answer(S)}),
        ),
        "an optional parameter becomes required": (
            cd.openapi_changes,
            api({"parameters": [q("a")], **answer(S)}),
            api({"parameters": [q("a", True)], **answer(S)}),
        ),
        "a request body becomes required": (
            cd.openapi_changes,
            api({"requestBody": {"required": False}, **answer(S)}, method="post"),
            api({"requestBody": {"required": True}, **answer(S)}, method="post"),
        ),
        "a response status disappears": (
            cd.openapi_changes,
            api({"responses": {**answer(S)["responses"], **answer(S, "404")["responses"]}}),
            api(answer(S)),
        ),
        "a response's JSON body disappears": (
            cd.openapi_changes,
            api(answer(S)),
            api({"responses": {"200": {"description": "ok"}}}),
        ),
        "a response's JSON body changes in a way the rules above call breaking": (
            cd.openapi_changes,
            api(answer(obj({"a": S}, ["a"]))),
            api(answer(obj({}))),
        ),
    },
}

ADDITIVE = {
    (BODY, "additive when:"): {
        "a new property appears, required or not": (cd.schema_changes, obj({}), obj({"a": S, "b": I}, ["a"])),
        "an optional property becomes required": (
            cd.schema_changes,
            obj({"a": S, "b": I}),
            obj({"a": S, "b": {"type": "integer", "description": "now set"}, "c": S}, ["a"]),
        ),
        "a type narrows, as `number` to `integer`": (
            cd.schema_changes,
            obj({"a": N}),
            obj({"a": I, "b": S}),
        ),
        "a closed list of values loses a value": (
            cd.schema_changes,
            obj({"a": {"type": "string", "enum": ["x", "y"]}}),
            obj({"a": {"type": "string", "enum": ["x"]}, "b": S}),
        ),
        'a list marked `"x-sipnab-open-enum": true` in both releases gains a value': (
            cd.schema_changes,
            obj({"a": {"type": "string", "enum": ["x"], "x-sipnab-open-enum": True}}),
            obj({"a": {"type": "string", "enum": ["x", "y"], "x-sipnab-open-enum": True}, "b": S}),
        ),
    },
    (OPS, "additive when:"): {
        "a new operation appears": (cd.openapi_changes, api(), api(answer(S))),
        "a new optional parameter appears": (
            cd.openapi_changes,
            api(answer(S)),
            api({"parameters": [q("a")], **answer(S)}),
        ),
        "a new response status appears": (
            cd.openapi_changes,
            api(answer(S)),
            api({"responses": {**answer(S)["responses"], **answer(S, "404")["responses"]}}),
        ),
        "a response's JSON body changes in a way the rules above call additive": (
            cd.openapi_changes,
            api(answer(obj({"a": S}))),
            api(answer(obj({"a": S, "b": I}))),
        ),
    },
}

UNCOMPARED = {
    (NOT, "does not compare:"): {
        "descriptions, titles, examples and the `info` object": (
            cd.openapi_changes,
            api(answer({"type": "string", "description": "a", "title": "a", "examples": ["a"]})),
            {
                **api(answer({"type": "string", "description": "b", "title": "b", "examples": ["b"]})),
                "info": {"title": "other", "version": "2"},
            },
        ),
        "the schema of a request body, and the schema of a parameter": (
            cd.openapi_changes,
            api(
                {
                    "parameters": [q("a", schema=S)],
                    "requestBody": {"content": {"application/json": {"schema": obj({"a": S})}}},
                    **answer(S),
                },
                method="post",
            ),
            api(
                {
                    "parameters": [q("a", schema=I)],
                    "requestBody": {"content": {"application/json": {"schema": obj({"b": I}, ["b"])}}},
                    **answer(S),
                },
                method="post",
            ),
        ),
        "a change inside `oneOf`, `anyOf`, `allOf` or `not`": (
            cd.schema_changes,
            {"oneOf": [S], "anyOf": [S], "allOf": [S], "not": S},
            {"oneOf": [I, {"type": "null"}], "anyOf": [I], "allOf": [I], "not": I},
        ),
        "bounds, patterns and formats, such as `minimum`, `maxLength`, `pattern` and `format`": (
            cd.schema_changes,
            {"type": "integer", "minimum": 0, "maximum": 9},
            {"type": "integer", "minimum": 5, "maximum": 99},
        ),
        "`additionalProperties`": (
            cd.schema_changes,
            obj({"a": S}, additionalProperties=False),
            obj({"a": S}, additionalProperties=I),
        ),
        "a response body of another media type than `application/json`": (
            cd.openapi_changes,
            api(answer(obj({"a": S}, ["a"]), media="text/plain")),
            api(answer(obj({}), media="text/plain")),
        ),
        "a JSON body added to a response that had none": (
            cd.openapi_changes,
            api({"responses": {"200": {"description": "ok"}}}),
            api(answer(S)),
        ),
    },
}


def _cases(table):
    return [pytest.param(key, rule, id=rule[:60]) for key, rules in table.items() for rule in rules]


def _changes(table, key, rule):
    fn, old, new = table[key][rule]
    return fn(old, new)


# ------------------------------------------------------------ success: rules


@pytest.mark.parametrize(("key", "rule"), _cases(ADDITIVE))
def test_success_each_additive_rule_is_additive(key, rule):
    changes = _changes(ADDITIVE, key, rule)
    assert changes, f"{rule!r}: the probe gave no change at all"
    assert all(c.kind == "additive" for c in changes), f"{rule!r}: {changes}"


# --------------------------------------------------------- success: examples


def _git_show(spec: str) -> bytes:
    r = subprocess.run(["git", "show", spec], cwd=REPO, capture_output=True, check=False, timeout=120)
    assert r.returncode == 0, (
        f"git show {spec} failed ({r.stderr.decode(errors='replace').strip()}); "
        "the page's examples need the release tags: run `git fetch --tags`"
    )
    return r.stdout


def _run_example(title: str, tmp_path) -> None:
    """Run the `sh` fence of section `title` the way a reader would, in
    `tmp_path`, and compare the script's output with the `text` fence."""
    blocks = fences(section(title))
    sh = [body for info, body in blocks if info == "sh"]
    text = [body for info, body in blocks if info == "text"]
    assert len(sh) == 1 and len(text) == 1, f"{title!r}: want one sh and one text fence, got {blocks}"
    command = None
    for line in sh[0]:
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[:2] == ["git", "show"]:
            assert len(words) == 5 and words[3] == ">", f"{title!r}: unexpected line {line!r}"
            (tmp_path / words[4]).write_bytes(_git_show(words[2]))
        elif words[:3] == ["python3", "-I", "scripts/contract-diff.py"]:
            command = words[3:]
        else:
            raise AssertionError(f"{title!r}: unexpected line {line!r}")
    assert command is not None, f"{title!r}: the fence runs no contract-diff.py"
    r = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *command],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert r.stderr == "", f"{title!r}: {r.stderr}"
    assert r.stdout.splitlines() == text[0], f"{title!r}: the script prints\n{r.stdout}"
    assert r.returncode == (1 if " 0 breaking" not in r.stdout else 0), f"{title!r}: exit {r.returncode}"


def test_success_the_rest_api_example_prints_what_the_page_shows(tmp_path):
    _run_example("Compare the REST API of two releases", tmp_path)


def test_success_the_report_schema_example_prints_what_the_page_shows(tmp_path):
    _run_example("Compare a report schema of two releases", tmp_path)


def test_success_the_verify_step_prints_what_the_page_shows():
    blocks = fences(section("Verify the script runs"))
    sh = [body for info, body in blocks if info == "sh"]
    text = [body for info, body in blocks if info == "text"]
    assert len(sh) == 1 and len(text) == 1, blocks
    lines = [line for line in sh[0] if not line.startswith("#")]
    assert lines[1:] == ['echo "exit $?"'], sh[0]
    words = shlex.split(lines[0])
    assert words[:3] == ["python3", "-I", "scripts/contract-diff.py"], words
    r = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *words[3:]],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert r.stdout.splitlines() + [f"exit {r.returncode}"] == text[0], r.stdout + r.stderr


# ------------------------------------------------------------ failure: rules


@pytest.mark.parametrize(("key", "rule"), _cases(BREAKING))
def test_failure_each_breaking_rule_is_breaking(key, rule):
    changes = _changes(BREAKING, key, rule)
    assert any(c.kind == "breaking" for c in changes), f"{rule!r}: {changes}"


# ---------------------------------------------------- failure: troubleshooting


def _main(tmp_path, kind, old, new):
    """Run main() on two documents (dicts are written as JSON, bytes as they
    are, None leaves the file absent): (exit, stderr)."""
    paths = []
    for name, doc in (("old.json", old), ("new.json", new)):
        p = tmp_path / name
        if isinstance(doc, bytes):
            p.write_bytes(doc)
        elif doc is not None:
            p.write_text(json.dumps(doc), encoding="utf-8")
        else:
            # An earlier call in the same tmp_path may have written it.
            p.unlink(missing_ok=True)
        paths.append(str(p))
    r = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--kind", kind, *paths],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return r.returncode, r.stderr


# The cause each troubleshooting entry names, and how to bring it about.
TRIGGERS = {
    "usage": lambda t: _main(t, "yaml", {}, {}),
    "missing file": lambda t: _main(t, "schema", {}, None),
    "not JSON": lambda t: _main(t, "schema", {}, b""),
    "remote ref": lambda t: _main(t, "schema", {}, {"$ref": "other.json#/a"}),
    "dangling ref": lambda t: _main(t, "schema", {}, {"$ref": "#/$defs/gone"}),
    "no paths": lambda t: _main(t, "openapi", {"type": "object"}, {"type": "object"}),
    "no tag": lambda t: (
        (r := subprocess.run(["git", "show", "v0.0.0-none:x"], cwd=REPO, capture_output=True, text=True, timeout=120)).returncode,
        r.stderr,
    ),
}


def troubles() -> dict[str, str]:
    """{the message a troubleshooting entry quotes: the entry's lead}."""
    out = {}
    for line in section("Troubleshoot"):
        m = re.match(r"^- \*\*(.+?)\*\*", line)
        if m:
            for span in code_spans(m.group(1)):
                out[span] = m.group(1)
    return out


@pytest.mark.parametrize("cause", sorted(TRIGGERS))
def test_failure_each_cause_prints_a_message_the_page_quotes(cause, tmp_path):
    rc, err = TRIGGERS[cause](tmp_path)
    assert rc != 0, f"{cause}: exit 0"
    quoted = [m for m in troubles() if m in err]
    assert quoted, f"{cause}: the page quotes no part of {err!r}"


def test_failure_the_exit_codes_are_the_ones_the_page_gives(tmp_path):
    assert "The script exits 0 when no change is breaking, 1 when one is, and 2 when it could not decide." in " ".join(
        " ".join(section("Read the result")).split()
    )
    assert _main(tmp_path, "schema", obj({}), obj({"a": S}))[0] == 0
    assert _main(tmp_path, "schema", obj({"a": S}), obj({}))[0] == 1
    assert _main(tmp_path, "schema", {}, None)[0] == 2


# --------------------------------------------------------- edge: not compared


@pytest.mark.parametrize(("key", "rule"), _cases(UNCOMPARED))
def test_edge_each_change_the_script_does_not_compare_gives_no_change(key, rule):
    assert _changes(UNCOMPARED, key, rule) == [], rule


# ---------------------------------------- edge: the page and the probes agree


@pytest.mark.parametrize(
    "table", [pytest.param(BREAKING, id="breaking"), pytest.param(ADDITIVE, id="additive"), pytest.param(UNCOMPARED, id="not-compared")]
)
def test_edge_the_page_lists_exactly_the_probed_rules(table):
    for (title, intro), rules in table.items():
        on_page = bullets_after(section(title), intro)
        assert on_page == list(rules), f"{title!r} {intro!r}: the page lists {on_page}, the probes {list(rules)}"


def test_edge_each_quoted_message_has_a_cause_here(tmp_path):
    printed = " ".join(TRIGGERS[cause](tmp_path)[1] for cause in TRIGGERS)
    unprobed = [m for m in troubles() if m not in printed]
    assert unprobed == [], f"the page quotes messages no cause here prints: {unprobed}"


def test_edge_the_usage_entry_quotes_the_usage_line_whole(tmp_path):
    _, err = TRIGGERS["usage"](tmp_path)
    assert err.strip() in troubles(), err


def _table_rows() -> list[tuple[str, str]]:
    """(linked file, kind) of each row of the surfaces table."""
    rows = []
    for line in section("The surfaces the script compares"):
        if not line.startswith("|") or set(line) <= set("|- "):
            continue
        link = re.search(r"\]\(\.\./([^)]+)\)", line)
        kind = re.search(r"\| `(\w+)` \|\s*$", line)
        if link and kind:
            rows.append((link.group(1), kind.group(1)))
    return rows


def test_edge_the_table_names_openapi_and_every_report_schema_sipnab_owns():
    owned = {"website/static/openapi.json"}
    for path in sorted((REPO / "tests" / "schemas").glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if str(doc.get("$id", "")).startswith("https://sipnab.com/"):
            owned.add(path.relative_to(REPO).as_posix())
    named = [path for path, _ in _table_rows()]
    assert sorted(named) == sorted(owned), f"the table names {named}; sipnab owns {sorted(owned)}"


def test_edge_each_row_names_the_kind_its_file_takes():
    for path, kind in _table_rows():
        want = "openapi" if path.endswith("openapi.json") else "schema"
        assert kind == want, f"{path}: the table says {kind!r}"


def test_edge_each_kind_on_the_page_is_one_the_usage_line_offers(tmp_path):
    _, err = TRIGGERS["usage"](tmp_path)
    offered = set(re.search(r"--kind (\S+)", err).group(1).split("|"))
    used = {kind for _, kind in _table_rows()}
    for _, body in fences(page().splitlines()):
        for line in body:
            m = re.search(r"contract-diff\.py --kind (\w+)", line)
            if m:
                used.add(m.group(1))
    assert used and used <= offered, f"the page uses {used}; the script offers {offered}"


def test_edge_the_open_enum_mark_is_the_one_the_script_reads():
    assert cd.OPEN_ENUM == "x-sipnab-open-enum"
    assert f'`"{cd.OPEN_ENUM}": true`' in page()


def test_edge_the_page_names_the_version_cargo_toml_holds():
    m = re.search(r'^version = "(\d+)\.(\d+)\.\d+"', (REPO / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    assert m, "Cargo.toml has no package version"
    assert m.group(1) == "0", "sipnab is at 1.0 or later: rewrite the page's promise for that release"
    assert f"sipnab is at {m.group(1)}.{m.group(2)}." in page()


def test_edge_each_tag_an_example_reads_holds_its_file():
    shown = []
    for _, body in fences(page().splitlines()):
        for line in body:
            words = shlex.split(line, comments=True)
            if words[:2] == ["git", "show"]:
                shown.append(words[2])
    assert len(shown) == 4, shown
    for spec in shown:
        assert _git_show(spec), f"{spec} is empty"
