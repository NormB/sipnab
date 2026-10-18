# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""An image in a published docs page renders from the site itself.

The site's CSP is `img-src 'self' data:`, so an image served from any other
origin is blocked. `build-site-pages.py` rewrote every relative link it did
not recognize to a GitHub blob URL, an image included: the blob URL is an
HTML page on another origin, so the image could not load for two reasons.
These tests drive the generator's own `render` and image copy.
"""

from conftest import load

SITE = load("build-site-pages")


def _render(body: str) -> str:
    getattr(SITE, "IMAGES", set()).clear()
    return SITE.render(
        "docs/example-page.md", "# Example\n\n" + body, "Example", "Example",
        1, "An example page.",
    )


def test_a_docs_image_renders_to_a_same_origin_path():
    out = _render("![The dialogs view](screenshots/sipnab-01-dialogs.png)\n")
    assert "](/doc-images/docs/screenshots/sipnab-01-dialogs.png)" in out
    assert SITE.BLOB not in out


def test_an_image_already_under_website_static_links_to_its_served_path():
    out = _render("![Hero](../website/static/demos/hero-static.webp)\n")
    assert "](/demos/hero-static.webp)" in out
    assert SITE.BLOB not in out
    assert SITE.IMAGES == set()


def test_a_non_image_repo_file_still_links_to_github():
    out = _render("See [the policy](../deny.toml).\n")
    assert f"]({SITE.BLOB}/deny.toml)" in out


def test_a_rendered_image_is_copied_to_the_path_it_is_linked_at(tmp_path):
    _render("![The dialogs view](screenshots/sipnab-01-dialogs.png)\n")
    SITE.copy_images(SITE.ROOT, tmp_path)
    copied = tmp_path / "doc-images" / "docs" / "screenshots" / "sipnab-01-dialogs.png"
    source = SITE.ROOT / "docs" / "screenshots" / "sipnab-01-dialogs.png"
    assert copied.read_bytes() == source.read_bytes()
