#!/usr/bin/env python3
"""Generate the surface-coverage matrix: every CLI flag, API route and MCP tool.

Generated, not written. The surface is 270-odd rows; a hand-maintained table
of that size is wrong within a week, and this repository has already paid for
hand-maintained numbers that drifted.

What the evidence tiers mean, and what this script can honestly establish:

  e2e        the token appears in a test that runs the real binary
  parsed     the token appears inside a `parse_from_args`/`parse_from` list,
             so a test drives it through clap
  referenced the token appears somewhere in the test corpus and nothing
             stronger was found -- which is NOT proof it is exercised
  none       no occurrence anywhere in the corpus

`referenced` is deliberately not called "tested". This repository's own
`flag_coverage_test` says of itself that it catches only "a flag nothing
anywhere mentions", and a tick derived from a mention is the kind of claim
that reads as coverage while proving nothing.

Nothing above `parsed` is inferred. A tier that needs judgement is left to a
human and marked as such rather than guessed here.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "design" / "testing-matrix.md"
BIN = ROOT / "target" / "debug" / "sipnab"


def strip_comments(src):
    """Rust source with comments removed.

    A flag named only in a `//` or `///` comment is not evidence of anything,
    and counting it is not a hypothetical mistake: `flag_coverage_test` carries
    its own `strip_rust_comments` because a single comment once "covered" three
    flags at once. The first version of this generator reproduced that exact
    bug, and an audit of its output found it -- three flags it reported as
    referenced were named only in doc comments.

    Tracks string literals so a `//` inside one does not start a comment.
    """
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\":
                    i += 2
                    if i <= n:
                        out.append(src[i - 1] if i - 1 < n else "")
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
            continue
        if src.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def corpus():
    """Every file a test could live in, with its text."""
    files = {}
    for d in ("tests", "src"):
        for p in (ROOT / d).rglob("*.rs"):
            try:
                files[p] = strip_comments(p.read_text(errors="replace"))
            except OSError:
                continue
    return files


def runs_the_binary(text):
    return "Command::new" in text or "cargo_bin" in text or "assert_cmd" in text


def arg_literals(text):
    """Text of every bracketed literal and `.arg("...")`, where CLI arguments
    are actually written.

    Membership in one of these is the difference between "a test that runs the
    binary happens to name this flag somewhere in the file" and "a test passed
    this flag to the binary". The first is worth almost nothing, and a
    file-level check quietly reports it as the second.
    """
    out = re.findall(r"\[[^\[\]]{0,400}\]", text, re.S)
    out += re.findall(r'\.arg\(\s*"[^"]+"\s*\)', text)
    return out


def parse_call_spans(text):
    """Argument text of every clap construction in this file."""
    spans = []
    for m in re.finditer(r"parse_from(?:_args)?\s*\(", text):
        i = m.end()
        depth, start = 1, i
        while i < len(text) and depth:
            if text[i] in "([":
                depth += 1
            elif text[i] in ")]":
                depth -= 1
            i += 1
        spans.append(text[start:i])
    return spans


# What actually drives a running surface in THIS repository's tests.
#
# Each entry is a real client-side idiom, and each is matched on a WHOLE
# IDENTIFIER rather than as a substring. The substring version of this list was
# wrong in the worst available way -- quietly, and in the direction of claiming
# coverage:
#
#   * `serve(` matched `observe(`, a local helper in
#     tests/arrival_order_parity_test.rs that has nothing to do with a server.
#     That file drives nothing, and every route or tool name it happened to
#     mention would have been reported as EXERCISED.
#   * `serve(` also matched `fn tls_flags_fail_fast_and_do_not_serve()`, which
#     is a test asserting the server did NOT start. tests/api_test.rs does drive
#     a server, thoroughly -- but the evidence this script cited for it was a
#     function name saying the opposite, and renaming that one test would have
#     silently downgraded every REST row in the matrix.
#
# `reqwest` was in the list and appears nowhere in the tree, which is the
# harmless half of the same mistake: a marker nobody can trigger.
SERVER_DRIVERS = (
    # REST: the in-tree harness that spawns a real sipnab and speaks HTTP to it.
    "ApiServer",
    # REST/metrics: a raw socket against a listening port.
    "TcpStream",
    # MCP over stdio: the JSON-RPC method, and the harness that sends it.
    "tools/call",
    "call_tool",
    "call_tool_with_args",
    "McpSession",
    # axum's own test path: a router driven in-process without a socket.
    "oneshot",
)


def drives_server(text):
    """Does this file actually exercise a running surface?

    An HTTP route or an MCP tool is not a command-line argument, so the
    CLI-shaped checks above cannot see them and every row collapsed to
    `referenced` -- a column that says the same thing about all 45 of them
    tells a reader nothing.

    Whole-identifier matching, for the reason SERVER_DRIVERS records above.
    """
    return any(uses_identifier(text, m) for m in SERVER_DRIVERS)


def uses_identifier(hay, needle):
    """Does `hay` use `needle` as a whole identifier?

    The same rule tests/surface_parity_test.rs applies, and for the same reason:
    a substring match reports a coincidence as evidence.
    """
    n = len(needle)
    for i in range(len(hay)):
        if not hay.startswith(needle, i):
            continue
        before = hay[i - 1] if i else ""
        after = hay[i + n] if i + n < len(hay) else ""
        if (before.isalnum() or before == "_") or (after.isalnum() or after == "_"):
            continue
        return True
    return False


def route_pattern(route):
    """A regex matching every way a test can write `route`.

    Axum spells a path parameter `{call_id}`; a test writes either its OWN
    placeholder name -- `format!("/v1/streams/{ssrc}")`, which is the literal
    text of an inline format argument -- or a concrete value,
    `"/v1/dialogs/12013223@example"`. Neither is the route string, so matching
    the route literally reported all three of sipnab's parameterized routes as
    `defined only` while tests/api_test.rs was driving every one of them.

    Each `{...}` becomes one path segment. The match is anchored on the right by
    a lookahead for `"` or `?`, so `/v1/dialogs/{call_id}` is NOT credited by a
    request to `/v1/dialogs/x/report` -- a different route, with its own row.
    """
    parts = re.split(r"\{[^}]*\}", route)
    return re.compile(r'[^"/?]+'.join(re.escape(p) for p in parts) + r'(?=["?])')


def classify_surface(name, files, is_route=False):
    """Evidence for a route or a tool: exercised by a test, or only defined."""
    exercised, defined = [], []
    pattern = route_pattern(name) if is_route else None
    quoted = f'"{name}"'
    for path, text in files.items():
        if pattern is not None:
            if not pattern.search(text):
                continue
        elif quoted not in text:
            continue
        rel = str(path.relative_to(ROOT))
        if rel.startswith("tests/") and drives_server(text):
            exercised.append(rel)
        else:
            defined.append(rel)
    if exercised:
        return "exercised", sorted(set(exercised))
    if defined:
        return "defined only", sorted(set(defined))
    return "none", []


def classify(token, files, short=""):
    """Strongest evidence for `token`, and where it came from.

    `short` matters more than it looks. Tests write `-d`, `-N` and `-I`, not
    `--device`, `--no-tui` and `--input`. Keyed on the long form alone, the
    most heavily exercised flags in the project reported as merely mentioned --
    a matrix that understates coverage is as untrustworthy as one that
    overstates it, and this one understated the three flags nearly every test
    uses.

    Exact quoted tokens for the argument-list checks: a bare `-d` matches
    inside any word, so substring matching would credit almost everything.
    """
    quoted = [f'"{token}"'] + ([f'"{short}"'] if short else [])
    hits, e2e, parsed = [], [], []
    for path, text in files.items():
        if token not in text and not (short and any(q in text for q in quoted)):
            continue
        rel = str(path.relative_to(ROOT))
        hits.append(rel)
        if runs_the_binary(text) and any(
            q in lit for lit in arg_literals(text) for q in quoted
        ):
            e2e.append(rel)
        if any(q in span for span in parse_call_spans(text) for q in quoted):
            parsed.append(rel)
    if e2e:
        return "e2e", sorted(set(e2e))
    if parsed:
        return "parsed", sorted(set(parsed))
    if hits:
        return "referenced", sorted(set(hits))
    return "none", []


def audited():
    """Human verdicts from `scripts/coverage-audit.tsv`, keyed by flag.

    Kept in a data file rather than derived, because it is not derivable: the
    difference between "a test names this flag" and "a test would fail if this
    flag stopped working" is a judgement about what the test asserts. The
    generator's own tiers understate for exactly that reason -- evidence that
    arrives through a config-file equivalent, a golden file or a library-level
    test is invisible to a token search.
    """
    path = ROOT / "scripts" / "coverage-audit.tsv"
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            out[parts[0]] = (parts[1], parts[2])
    return out


def cli_flags():
    """(heading, short, long, takes_value) from the binary's own help."""
    if not BIN.exists():
        sys.exit(f"build the binary first: {BIN} is missing")
    help_text = subprocess.run(
        [str(BIN), "--help"], capture_output=True, text=True, check=False
    ).stdout
    heading, out = "Options", []
    for line in help_text.splitlines():
        # Headings carry punctuation -- "MCP (Model Context Protocol):",
        # "TLS / Decryption:". A tighter character class silently dropped those
        # headings, and every flag beneath one inherited the heading ABOVE it,
        # so the Group column lied for a whole section without failing anything.
        h = re.match(r"^([A-Za-z][^:]*):$", line)
        if h:
            heading = h.group(1)
            continue
        m = re.match(r"^\s{2,6}(?:(-[A-Za-z]), )?(--[a-z0-9-]+)(\s+<([A-Z_]+)>)?", line)
        if m:
            out.append((heading, m.group(1) or "", m.group(2), m.group(4) or ""))
    # `--help` lists only what clap advertises. A `hide = true` flag is still
    # surface a user can pass -- `--panic-selftest` deliberately crashes the
    # process -- and a coverage matrix that omits it describes the advertised
    # program rather than the real one. Read those out of the source.
    cli_rs = (ROOT / "src" / "cli.rs").read_text()
    for attr in re.findall(r"#\[arg\((.*?)\)\]", cli_rs, re.S):
        if "hide = true" not in attr:
            continue
        long = re.search(r'long\s*=\s*"([a-z0-9-]+)"', attr)
        if not long:
            continue
        head = re.search(r'help_heading\s*=\s*"([^"]+)"', attr)
        out.append(((head.group(1) if head else "Options") + " (hidden)", "",
                    f"--{long.group(1)}", ""))

    seen, uniq = set(), []
    for row in out:
        if row[2] not in seen:
            seen.add(row[2])
            uniq.append(row)
    return uniq


def api_routes():
    text = (ROOT / "src" / "output" / "api.rs").read_text()
    return sorted(set(re.findall(r'\.route\(\s*"([^"]+)"', text)))


def mcp_tools():
    # Every file under src/mcp/, not just server.rs. Tool groups live in their
    # own modules since the router became composable, and a scanner that reads
    # only server.rs reports the old count while the new tools are live and
    # undocumented -- the parity gate would certify a surface it cannot see.
    text = "\n".join(
        f.read_text()
        for f in sorted((ROOT / "src" / "mcp").rglob("*.rs"))
    )
    return sorted(set(re.findall(r'#\[tool\(\s*name\s*=\s*"([^"]+)"', text)))


def cite(paths, limit=2):
    if not paths:
        return "--"
    shown = ", ".join(f"`{p}`" for p in paths[:limit])
    return shown + (f" +{len(paths) - limit}" if len(paths) > limit else "")


def table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def main():
    files = corpus()
    flags, routes, tools = cli_flags(), api_routes(), mcp_tools()

    audit = audited()
    tally, verdicts = {}, {}
    flag_rows = []
    for heading, short, long, val in flags:
        tier, where = classify(long, files, short)
        tally[tier] = tally.get(tier, 0) + 1
        verdict, evidence = audit.get(long, ("", ""))
        if verdict:
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        flag_rows.append(
            [f"`{long}`", f"`{short}`" if short else "", f"`{val}`" if val else "",
             heading, tier, cite(where), f"**{verdict}**" if verdict else "",
             evidence]
        )

    route_rows = []
    for r in routes:
        tier, where = classify_surface(r, files, is_route=True)
        route_rows.append([f"`{r}`", tier, cite(where)])

    tool_rows = []
    for t in tools:
        tier, where = classify_surface(t, files)
        tool_rows.append([f"`{t}`", tier, cite(where)])

    untested = [r[0] for r in flag_rows if r[4] == "none"]
    beh = verdicts.get("behavior", 0)
    po = verdicts.get("parse-only", 0)
    mo = verdicts.get("mention-only", 0)
    ref_n = tally.get("referenced", 0)
    if untested:
        coverage_note = "**Flags with no occurrence at all:** " + ", ".join(untested)
    else:
        coverage_note = (
            "**No row can ever say `none`, and that is the point.** "
            "`flag_coverage_test` already requires every flag's `--name` token "
            "to appear somewhere in the test corpus, and it defines "
            "\"referenced\" as exactly that. A coverage metric built on "
            "mentions therefore reports 100% for this project no matter what "
            "is actually exercised -- which is what a yes/no \"tested\" "
            "column would have shown. The rows at `referenced` are the ones "
            "that gate passes and this document does not."
        )
    body = f"""# Surface coverage matrix

**Generated by `scripts/coverage-matrix.py`. Do not edit by hand.**

Every command-line flag, HTTP route and MCP tool sipnab exposes, with what the
test corpus can be shown to do with it. Regenerate with:

```sh
cargo build --features full && python3 scripts/coverage-matrix.py
```

## What a tier claims, and what it does not

| Tier | Established by | What it proves |
|---|---|---|
| `e2e` | the flag appears in an ARGUMENT LIST in a test that executes the real binary | a test drove the binary with it |
| `parsed` | the token appears inside a `parse_from_args` list | clap accepts it; behavior is unproven |
| `referenced` | the token appears in the corpus, nothing stronger | **nothing.** A mention is not an exercise |
| `none` | no occurrence anywhere | untested surface |

`referenced` is deliberately not spelled "tested". This repository's own
`flag_coverage_test` says it catches only "a flag nothing anywhere mentions",
and a tick derived from a mention reads as coverage while proving nothing.

The tiers above `parsed` need a human to distinguish "a test names this" from
"a test would fail if this broke". This generator does not guess at that, and
no row here should be read as a mutation-checked guarantee unless a person
put it there.

HTTP routes and MCP tools are not command-line arguments and use their own two
tiers:

| Tier | Established by | What it proves |
|---|---|---|
| `exercised` | the route or tool is named in a test file that also drives a running surface | a test reached it through the door users reach it through |
| `defined only` | it is named, but nowhere that drives anything | it exists; nothing here reached it |

"Drives a running surface" means the file uses one of a named set of client
idioms -- the REST test harness, a raw socket, an MCP session, a `tools/call`.
A route is matched allowing for its path parameters, because a test writes
`format!("/v1/streams/{{ssrc}}")` or a concrete SSRC where the route says
`{{id}}`. Both of those rules used to be substring tests, and both were wrong in
the direction of a wrong answer rather than no answer: `serve(` matched
`observe(` in a file that drives nothing, and matching a route literally
reported every parameterized route as `defined only` while the REST test suite
was driving all of them.

## Totals

| Surface | Rows | `e2e` | `parsed` | `referenced` | `none` |
|---|---|---|---|---|---|
| CLI flags | {len(flag_rows)} | {tally.get('e2e', 0)} | {tally.get('parsed', 0)} | {tally.get('referenced', 0)} | {tally.get('none', 0)} |
| HTTP routes | {len(route_rows)} | {sum(1 for r in route_rows if r[1] == 'exercised')} | -- | {sum(1 for r in route_rows if r[1] == 'defined only')} | {sum(1 for r in route_rows if r[1] == 'none')} |
| MCP tools | {len(tool_rows)} | {sum(1 for r in tool_rows if r[1] == 'exercised')} | -- | {sum(1 for r in tool_rows if r[1] == 'defined only')} | {sum(1 for r in tool_rows if r[1] == 'none')} |

{coverage_note}

## What a person found that the detector could not

The generator understates. Of the {ref_n} flags it could only call
`referenced`, a read of the tests found {beh} with a real behavior test --
evidence that arrives through a config-file equivalent sharing the flag's
resolver, through a golden file, or through a library-level test, none of
which a token search can see.

| Audited verdict | Flags | What it means |
|---|---|---|
| `behavior` | {beh} | a test asserts an observable effect; it fails if the flag stops working |
| `parse-only` | {po} | a test drives it through clap and asserts nothing downstream |
| `mention-only` | {mo} | the token appears; nothing exercises it |

The `parse-only` and `mention-only` rows are the finding. Several guard things
that fail silently when inert: a credential, two command-execution hooks, three
connection and row ceilings, an intrusion detector, and two safety switches
whose whole purpose is to weaken the process on request. A flag that guards
nothing and says nothing is indistinguishable from a quiet network.

Read the `Audited` column per row for which is which. Rows with no audited
verdict were not read by a person -- the `Detected` column is all that stands
behind them.

## CLI flags

{table(flag_rows, ["Flag", "Short", "Value", "Group", "Detected", "Where", "Audited", "What a person found"])}

## HTTP routes

{table(route_rows, ["Route", "Evidence", "Where"])}

## MCP tools

{table(tool_rows, ["Tool", "Evidence", "Where"])}
"""
    OUT.write_text(body)
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  CLI flags   {len(flag_rows):>4}  {tally}")
    print(f"  HTTP routes {len(route_rows):>4}")
    print(f"  MCP tools   {len(tool_rows):>4}")


if __name__ == "__main__":
    main()
