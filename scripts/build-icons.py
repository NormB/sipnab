#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Draw the logo files from website/brand/mark.svg.

The mark is a SIP call ladder: two amber rails, a request and its response,
on the site's dark tile, on a 32-unit grid. Every other logo file is drawn
from it here, so a change to the mark is one edit and one run:

- website/static/favicon.svg, the mark itself;
- website/static/favicon.ico, 16, 32 and 48 pixel PNG images in one ICO;
- website/static/apple-touch-icon.png, 180 pixels, square, because iOS
  rounds the corners itself;
- website/og-image.svg, the social card, whose marked place gets the mark,
  and website/static/og-image.png, that card drawn at 1200 by 630;
- website/brand/social-preview.png, the same card centered on GitHub's
  1280 by 640 repository preview;
- website/brand/lockup-dark.svg and lockup-light.svg, the mark and the name
  for dark and light backgrounds.

The name in the lockups is JetBrains Mono Bold, the site's wordmark face,
turned to outlines, so the files embed no font and need none to show. The
card's text is drawn by resvg from the font files fc-match names, and only
from those: system fonts are switched off, so a missing face stops the run
instead of shipping a fallback (the 2026-07-18 demo renders did exactly that).

Needs resvg on PATH, the fontTools Python package, and JetBrains Mono and
Inter installed where fc-match finds them. Run from the repository root:

    python3 scripts/build-icons.py           # write every file
    python3 scripts/build-icons.py --check   # exit 1 naming any file that differs

The PNG bytes depend on the resvg and font versions, so --check is for the
machine that last wrote them, not for CI. CI holds the committed files to
their shape instead (tests/site_journey_test.rs).
"""

import argparse
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "website/brand"
STATIC = ROOT / "website/static"
MARK = BRAND / "mark.svg"
CARD = ROOT / "website/og-image.svg"

# The site's palette (website/sass/style.scss).
AMBER = "#ffcc66"
INK = "#0a0e14"

# Where the card draws the mark: x, y and size in card pixels. It takes the
# place of the old "s" tile, left of the wordmark.
CARD_MARK = (98, 120, 80)
MARK_OPEN = "<!-- mark: drawn by scripts/build-icons.py from website/brand/mark.svg -->"
MARK_CLOSE = "<!-- /mark -->"

# The faces resvg may use for the card: (fc-match pattern, family it must be).
CARD_FONTS = (
    ("JetBrains Mono:style=Regular", "JetBrains Mono"),
    ("JetBrains Mono:style=Medium", "JetBrains Mono"),
    ("JetBrains Mono:style=Bold", "JetBrains Mono"),
    ("Inter:style=SemiBold", "Inter"),
)


class IconError(Exception):
    """An input is not in the shape this script draws from."""


def mark_body(mark: str) -> str:
    """The mark's drawing without its <svg> element, on the 32-unit grid."""
    return mark[mark.index(">") + 1:mark.rindex("</svg>")].strip()


def placed(x: int, y: int, size: int, body: str) -> str:
    """`body`, drawn on the 32-unit grid, as a `size`-pixel square at x, y."""
    scale = size / 32
    return f'<g transform="translate({x} {y}) scale({scale:g})">{body}</g>'


def splice(card: str, mark: str) -> str:
    """The card with the mark drawn in its one marked place."""
    if card.count(MARK_OPEN) != 1 or card.count(MARK_CLOSE) != 1:
        raise IconError(f"the card must hold {MARK_OPEN} and {MARK_CLOSE} once each")
    head, rest = card.split(MARK_OPEN)
    _, tail = rest.split(MARK_CLOSE)
    indent = head[head.rindex("\n") + 1:]
    return f"{head}{MARK_OPEN}\n{indent}{placed(*CARD_MARK, mark_body(mark))}\n{indent}{MARK_CLOSE}{tail}"


def square(mark: str) -> str:
    """The mark on a square tile, for icons whose platform rounds the corners."""
    tile = '<rect width="32" height="32" rx="6" '
    if mark.count(tile) != 1:
        raise IconError("the mark's tile is not the one 32-unit rect with rx=6")
    return mark.replace(tile, '<rect width="32" height="32" ')


def ico(pngs) -> bytes:
    """An ICO file holding PNG images, which every current browser reads.

    `pngs` is (size, PNG bytes) pairs. The directory gives each image's size
    in one byte, so 256 is written as 0, as the format defines.
    """
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = len(header) + 16 * len(pngs)
    entries, data = b"", b""
    for size, png in pngs:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return header + entries + data


def preview(card: str, width: int, height: int) -> str:
    """The card centered on a `width` by `height` canvas of the card's ink."""
    open_tag = card[:card.index(">") + 1]
    w = int(open_tag.split('width="')[1].split('"')[0])
    h = int(open_tag.split('height="')[1].split('"')[0])
    if w > width or h > height:
        raise IconError(f"the card is {w}x{h}, larger than the {width}x{height} canvas")
    body = card[len(open_tag):card.rindex("</svg>")]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" fill="{INK}"/>'
        f'<g transform="translate({(width - w) // 2} {(height - h) // 2})">{body}</g></svg>\n'
    )


def stale(outputs) -> list:
    """The paths in `outputs` whose file is missing or differs from its bytes."""
    return [p for p, content in outputs.items() if not p.exists() or p.read_bytes() != content]


def font_file(pattern: str, family: str) -> str:
    """The file fc-match gives for `pattern`, refused unless it is `family`."""
    found = subprocess.run(
        ["fc-match", "-f", "%{file}\t%{family}", pattern],
        check=True, capture_output=True, text=True,
    ).stdout
    path, families = found.split("\t", 1)
    if family not in families.split(","):
        raise IconError(f"fc-match gave {path} ({families}) for {pattern}, not {family}")
    return path


def lockup(color: str) -> bytes:
    """The mark and the name, 64 pixels high, the name in `color`."""
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont

    face = TTFont(font_file("JetBrains Mono:style=Bold", "JetBrains Mono"))
    size, x, baseline = 44, 80, 46
    scale = size / face["head"].unitsPerEm
    glyphs, cmap = face.getGlyphSet(), face.getBestCmap()
    pen = SVGPathPen(glyphs)
    for char in "sipnab":
        name = cmap[ord(char)]
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
        # -0.02em, the tracking the site's nav-logo sets.
        x += glyphs[name].width * scale - 0.02 * size
    width = round(x) + 4
    body = placed(0, 0, 64, mark_body(MARK.read_text())) + f'<path d="{pen.getCommands()}" fill="{color}"/>'
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="64" '
        f'viewBox="0 0 {width} 64">{body}</svg>\n'
    ).encode()


def render(svg: str, width: int, height: int) -> bytes:
    """`svg` as a `width` by `height` PNG, text in the card's faces only."""
    fonts = []
    for pattern, family in CARD_FONTS:
        fonts += ["--use-font-file", font_file(pattern, family)]
    with tempfile.TemporaryDirectory() as tmp:
        source, target = Path(tmp, "in.svg"), Path(tmp, "out.png")
        source.write_text(svg)
        subprocess.run(
            ["resvg", "--skip-system-fonts", *fonts, "-w", str(width), "-h", str(height), str(source), str(target)],
            check=True,
        )
        return target.read_bytes()


def outputs() -> dict:
    """Every file this script writes, by path, as the bytes it should hold."""
    mark = MARK.read_text()
    card = splice(CARD.read_text(), mark)
    return {
        STATIC / "favicon.svg": mark.encode(),
        STATIC / "favicon.ico": ico([(s, render(mark, s, s)) for s in (16, 32, 48)]),
        STATIC / "apple-touch-icon.png": render(square(mark), 180, 180),
        CARD: card.encode(),
        STATIC / "og-image.png": render(card, 1200, 630),
        BRAND / "social-preview.png": render(preview(card, 1280, 640), 1280, 640),
        BRAND / "lockup-dark.svg": lockup(AMBER),
        BRAND / "lockup-light.svg": lockup(INK),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if any file differs")
    args = ap.parse_args(argv)
    try:
        files = outputs()
    except IconError as e:
        print(f"build-icons: {e}", file=sys.stderr)
        return 1
    if args.check:
        bad = stale(files)
        for path in bad:
            print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
        if bad:
            print("Fix: python3 scripts/build-icons.py", file=sys.stderr)
        return 1 if bad else 0
    for path, content in files.items():
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
