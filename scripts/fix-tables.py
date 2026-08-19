"""Repair tables broken by the IANA-registry scrape, in three docs.

A markdown table row must be one line. Twelve rows in sip-header-fields.md are
split across two, because the source registry wraps long "Reference" cells:

    | Additional-Identity |  | [3GPP TS 24.229 v16.7.0]
            [Dongwook_Kim] |  |

Markdown ends the table at the first line that is not a row, so the break at
line 60 drops roughly 128 of 136 rows to plain text. The page looks fine until
the point a reader is most likely to scroll to.

Two further artifacts come from the same scrape:

* `[3GPP TS 24.229 v16.7.0]` has no link definition anywhere in the file, so it
  renders as literal bracketed text -- it LOOKS like a link and is not one.
  3GPP specs are not on rfc-editor.org; the portal page is the citable target.
* `[Dongwook_Kim]` is the registry's Contact column. It is a person's name with
  no link and no meaning to a reader of this table, and it is dropped.
"""
import pathlib, re, sys

# Derived from this file's location, like every sibling script
# (`check-line-drift.py` and `rfc-links.py` both use the same `parents[1]`).
# It was an absolute `/home/gator/Development/sipnab`, which exists on exactly
# one machine. Measured 2026-08-19 on macOS/aarch64 at
# /Users/gator/Development/sipnab: the first `read_text()` raised
# `FileNotFoundError: '/home/gator/Development/sipnab/docs/sip-header-fields.md'`.
# `tests/doc_link_hygiene_test.rs:380` fails with "Run scripts/fix-tables.py
# --apply", so the gate's only remedy was a script that could not start
# anywhere but one checkout.
ROOT = pathlib.Path(__file__).resolve().parents[1]
# Verified 200; www.3gpp.org/DynaReport/24229.htm returns 403.
TS_24229 = ("https://portal.3gpp.org/desktopmodules/Specifications/"
            "SpecificationDetails.aspx?specificationId=1055")
CONTACT = re.compile(r"\s*\[[A-Za-z]+_[A-Za-z]+\]")
SPEC = re.compile(r"\[(3GPP TS 24\.229(?: v[0-9.]+)?)\](?!\()")


def join_rows(lines: list[str]) -> tuple[list[str], int]:
    """Fold a continuation line back onto the row it belongs to."""
    out, joined = [], 0
    for line in lines:
        if (out and out[-1].lstrip().startswith("|")
                and out[-1].count("|") < 5
                and not line.lstrip().startswith("|")
                and line.strip()):
            out[-1] = out[-1].rstrip() + " " + line.strip()
            joined += 1
            continue
        out.append(line)
    return out, joined


def convert(text: str) -> tuple[str, int, int]:
    lines, joined = join_rows(text.split("\n"))
    n_link = 0
    for i, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        new = CONTACT.sub("", line)
        new, k = SPEC.subn(lambda m: f"[{m.group(1)}]({TS_24229})", new)
        n_link += k
        lines[i] = new
    return "\n".join(lines), joined, n_link


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    for name in ("sip-header-fields.md", "sip-methods.md", "sip-response-codes.md"):
        f = ROOT / "docs" / name
        orig = f.read_text()
        out, joined, linked = convert(orig)
        if out != orig:
            print(f"  {name}: {joined} rows rejoined, {linked} 3GPP refs linked")
            if apply:
                f.write_text(out)
        else:
            print(f"  {name}: nothing to fix")
