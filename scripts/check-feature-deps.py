#!/usr/bin/env python3
"""Fail if a feature-gated module imports a crate its feature does not declare.

`--features vcon` did not build at 0.5.130: `src/output/redact.rs` is gated by
`any(api, mcp, vcon)` and imports `hmac`, and only two of those three features
declared `dep:hmac`. `--features full` hid it, because `mcp` pulls `hmac` in
anyway, so every ordinary build passed while one matrix combination did not.

The feature matrix in `.githooks/pre-push` is supposed to catch this and did
not, for a reason worth keeping: it builds the WORKING TREE, and the working
tree held the fix. Only the commit lacked it. A gate whose input is not the
thing being shipped reports on something nobody is shipping.

This reads the source instead of building it, so it costs milliseconds rather
than eleven compilations, and it names the file, the crate and the feature
rather than an unresolved-import error thirty lines into a build log.
"""

import re
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def optional_crates(cargo: str) -> set[str]:
    """Crates declared `optional = true`, which a feature must opt into."""
    return set(re.findall(r'(?m)^([A-Za-z0-9_-]+) = \{[^\n]*optional = true', cargo))


def feature_table(cargo: str) -> dict[str, list[str]]:
    """`[features]` as a map, entries verbatim."""
    section = cargo.split("[features]", 1)[1].split("\n[", 1)[0]
    return {
        m.group(1): [x.strip().strip('"') for x in m.group(2).split(",") if x.strip()]
        for m in re.finditer(r'(?m)^([a-z0-9_-]+) = \[([^\]]*)\]', section)
    }


def deps_of(feature: str, feats: dict[str, list[str]], seen=None) -> set[str]:
    """Crates a feature pulls in, TRANSITIVELY.

    `vcon = ["native", ...]` inherits everything `native` declares, and a check
    that ignored that would report a false problem for every crate a parent
    feature supplies.
    """
    seen = seen or set()
    if feature in seen:
        return set()
    seen.add(feature)
    out: set[str] = set()
    for entry in feats.get(feature, []):
        if entry.startswith("dep:"):
            out.add(entry[4:])
        elif entry in feats:
            out |= deps_of(entry, feats, seen)
    return out


def cfg_alternatives(expr: str) -> list[set[str]]:
    """The feature sets that each, on their own, compile the module.

    `any(a, b)` yields TWO: a build enabling only `a` compiles the file, and so
    does one enabling only `b`, so each must supply the imports by itself.
    Treating those as a union is the reasoning that let the 0.5.130 bug ship.

    `all(a, b)` yields ONE set holding both. No build compiles the file with
    half of it, so the pair supplies the imports together. Reading an `all` as
    two alternatives demands that each half declare the other's crates to
    satisfy a build that cannot exist -- and `src/mcp/tools/vcon.rs`, gated
    `all(mcp, vcon)`, is exactly that: it needs `rmcp`, which `mcp` supplies
    and `vcon` has no business pulling in.

    Anything mixing the two, or shaped in a way this does not recognize, falls
    back to the STRICT reading -- one alternative per feature. A parser that
    guesses permissively when it is confused is a gate that opens when it stops
    understanding what it is looking at.
    """
    names = re.findall(r'feature = "([a-z0-9_-]+)"', expr)
    if not names:
        return []
    body = expr.strip()
    if body.startswith("all(") and "any(" not in body:
        return [set(names)]
    return [{n} for n in names]


def gated_modules() -> dict[pathlib.Path, list[set[str]]]:
    """Each module behind a `#[cfg(feature = ..)]`, and the feature sets that
    compile it -- see [`cfg_alternatives`] for what "alternative" means here."""
    found: dict[pathlib.Path, list[str]] = {}
    for modfile in ROOT.glob("src/**/mod.rs"):
        lines = modfile.read_text().split("\n")
        for i, line in enumerate(lines):
            cfg = re.match(r'\s*#\[cfg\((.*)\)\]\s*$', line)
            if not cfg:
                continue
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            decl = re.match(r'\s*(?:pub )?mod ([a-z0-9_]+);', nxt)
            if not decl:
                continue
            names = cfg_alternatives(cfg.group(1))
            if not names:
                continue
            target = modfile.parent / f"{decl.group(1)}.rs"
            if not target.exists():
                target = modfile.parent / decl.group(1) / "mod.rs"
            if target.exists():
                found[target] = names
    return found


def main() -> int:
    cargo = (ROOT / "Cargo.toml").read_text()
    optional = optional_crates(cargo)
    feats = feature_table(cargo)
    modules = gated_modules()

    # A walk that finds nothing reports zero problems, which is the shape this
    # repository keeps catching: a gate that cannot see its subject looks
    # exactly like a subject with nothing wrong.
    if len(modules) < 10:
        print(
            f"only {len(modules)} feature-gated modules found; the scan is not "
            f"reaching src/ and a pass would mean nothing",
            file=sys.stderr,
        )
        return 2
    if len(optional) < 5:
        print(
            f"only {len(optional)} optional crates parsed from Cargo.toml; the "
            f"dependency table shape changed and nothing can be checked",
            file=sys.stderr,
        )
        return 2

    problems = []
    for path, names in sorted(modules.items()):
        text = path.read_text()
        used = {
            crate
            for crate in optional
            if re.search(rf'(?m)^\s*use {re.escape(crate)}(::|\s|;)', text)
        }
        for alternative in names:
            supplied: set[str] = set()
            for feature in alternative:
                supplied |= deps_of(feature, feats)
            for crate in sorted(used - supplied):
                rel = path.relative_to(ROOT)
                enabled = ",".join(sorted(alternative))
                problems.append(
                    f"  {rel}: imports `{crate}`, but feature `{enabled}` does "
                    f"not declare `dep:{crate}`. A build enabling only "
                    f"`{enabled}` compiles this file and fails on the import."
                )

    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked {len(modules)} feature-gated modules")
    return 1 if problems else 0


if __name__ == "__main__":
    # An optional root, so the RULE can be driven against a fixture tree rather
    # than only against this repository. A rule that can be exercised on one
    # input is a rule whose branches nobody has seen.
    if len(sys.argv) > 1:
        ROOT = pathlib.Path(sys.argv[1]).resolve()
    sys.exit(main())
