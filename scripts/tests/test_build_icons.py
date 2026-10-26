# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/build-icons.py: the logo files drawn from website/brand/mark.svg.

These drive the script's pure parts: they need neither resvg nor fontTools,
which CI's Python job does not install. The drawing itself is checked on the
committed files by tests/site_journey_test.rs.
"""

import struct

import pytest

from conftest import load

icons = load("build-icons")

MARK = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#0a0e14"/>'
    '<path d="M8 6.5v19" stroke="#ffcc66"/></svg>\n'
)
BODY = '<rect width="32" height="32" rx="6" fill="#0a0e14"/><path d="M8 6.5v19" stroke="#ffcc66"/>'


def card(between="old drawing"):
    return (
        '<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">\n'
        '  <rect width="1200" height="630" fill="#0a0e14"/>\n'
        f"  {icons.MARK_OPEN}\n  {between}\n  {icons.MARK_CLOSE}\n"
        "</svg>\n"
    )


def test_the_mark_body_is_the_drawing_without_its_svg_element():
    assert icons.mark_body(MARK) == BODY


def test_splice_puts_the_mark_between_the_markers_at_the_card_place():
    out = icons.splice(card(), MARK)
    assert "old drawing" not in out
    assert icons.placed(*icons.CARD_MARK, BODY) in out
    assert out.startswith('<svg width="1200"') and out.endswith("</svg>\n")


def test_splice_is_idempotent():
    once = icons.splice(card(), MARK)
    assert icons.splice(once, MARK) == once


@pytest.mark.parametrize("text", [
    card().replace(icons.MARK_OPEN, ""),                  # no opening marker
    card().replace(icons.MARK_CLOSE, ""),                 # no closing marker
    card().replace("</svg>", f"{icons.MARK_OPEN}</svg>"),  # two openings
])
def test_splice_refuses_a_card_without_exactly_one_marked_place(text):
    with pytest.raises(icons.IconError):
        icons.splice(text, MARK)


def test_placed_scales_the_32_unit_grid_to_the_size():
    assert icons.placed(96, 140, 64, "X") == '<g transform="translate(96 140) scale(2)">X</g>'


def test_square_drops_only_the_tile_corner_radius():
    out = icons.square(MARK)
    assert '<rect width="32" height="32" fill="#0a0e14"/>' in out
    assert "rx=" not in out
    assert '<path d="M8 6.5v19" stroke="#ffcc66"/>' in out


def test_square_refuses_a_mark_whose_tile_it_cannot_find():
    with pytest.raises(icons.IconError):
        icons.square(MARK.replace(' rx="6"', ""))


def test_ico_directory_points_at_each_png():
    pngs = [(16, b"sixteen"), (32, b"thirty-two"), (256, b"big")]
    data = icons.ico(pngs)
    assert struct.unpack_from("<HHH", data, 0) == (0, 1, 3)
    for i, (size, png) in enumerate(pngs):
        w, h, colors, _, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        # 256 is written as 0: the field is one byte.
        assert (w, h) == (size % 256, size % 256)
        assert (colors, planes, bits) == (0, 1, 32)
        assert data[offset:offset + length] == png


def test_preview_centers_the_card_on_the_larger_canvas():
    out = icons.preview(card("x"), 1280, 640)
    assert out.startswith('<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640">')
    assert '<g transform="translate(40 5)">' in out
    assert out.count("<svg") == 1


def test_preview_refuses_a_canvas_smaller_than_the_card():
    with pytest.raises(icons.IconError):
        icons.preview(card(), 1000, 640)


def test_stale_names_only_the_files_that_differ(tmp_path):
    same, changed, missing = tmp_path / "same", tmp_path / "changed", tmp_path / "missing"
    same.write_bytes(b"a")
    changed.write_bytes(b"b")
    assert icons.stale({same: b"a", changed: b"c", missing: b"d"}) == [changed, missing]
