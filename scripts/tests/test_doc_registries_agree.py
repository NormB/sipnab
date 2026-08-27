"""A published docs page must appear in EVERY registry, not most of them.

Adding one page to `docs/` requires six separate registrations, and nothing
checked them together. They were found one failed gate at a time -- the site
generator, then the wiki generator, then the link-rewriting map, then three
navigation templates, then the docs index -- each discovered only after fixing
the one before it.

Each registry has its own gate and its own failure message, and every one of
those messages is good. What none of them could say is "here is the full set of
places this page has to be named". That is what this file is.

The registries, and what a page missing from one costs:

* `build-site-pages.py` PAGES -- the site page is never generated at all.
* `DOCS_TO_SITE` in `build-site-internals.py` -- links to the page rewrite to
  GitHub blob URLs, sending readers past the site page that exists.
* `build-wiki.py` PAGES -- the wiki build refuses outright: "it would publish
  nowhere".
* `build-wiki.py` sections -- the page publishes to the wiki with no section,
  so the wiki index cannot reach it.
The three navigation templates are deliberately NOT checked here.
`every_docs_page_is_in_the_sidebar_and_dropdown_navs` already compares them
against `website/content/docs/*.md`, which is the right set; a second check
built on a different set reported eight pages as missing that were never meant
to be in a sidebar.
* `docs/README.md` -- a reader starting at the index cannot reach it.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def published_pages() -> list[str]:
    """Every page `build-site-pages.py` actually publishes.

    Derived from the generator rather than from a `docs/*.md` glob, because the
    two are different sets and the glob is the wrong one: `docs/fault-model.md`
    is a reader-facing page that the site does not carry, and a check built on
    the glob reports it as missing from four registries it was never meant to
    be in. The generator is the definition of "published".
    """
    src = (ROOT / "scripts" / "build-site-pages.py").read_text(encoding="utf-8")
    return sorted(set(re.findall(r'"docs/([a-z0-9-]+\.md)"', src)))


PAGES = published_pages()


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def site_name(page: str) -> str:
    """The name a source page publishes under.

    Not the same string: `tui-walkthrough.md` publishes as `tui.md`,
    `cli-reference.md` as `cli.md`, `examples.md` as `cookbook.md`. The
    navigation templates and the site tree use the PUBLISHED name, and a check
    that compared source names would fail on every renamed page while passing
    on a page that is genuinely missing.
    """
    src = read("scripts/build-site-internals.py")
    m = re.search(rf'"{re.escape(page)}":\s*"([^"]+)"', src)
    return m.group(1) if m else page


@pytest.mark.parametrize("page", PAGES)
def test_the_site_generator_knows_about_the_page(page):
    """Without this the site page is never written."""
    src = read("scripts/build-site-pages.py")
    assert f'"docs/{page}"' in src, (
        f"docs/{page} is in no PAGES entry of build-site-pages.py, so no site "
        f"page is generated for it"
    )


@pytest.mark.parametrize("page", PAGES)
def test_links_to_the_page_rewrite_to_the_site_and_not_to_github(page):
    """Without this, every link to the page becomes a GitHub blob URL."""
    src = read("scripts/build-site-internals.py")
    assert f'"{page}"' in src, (
        f"{page} is not a DOCS_TO_SITE key, so links to it rewrite to a blob "
        f"URL and send readers to GitHub past the site page that exists"
    )


@pytest.mark.parametrize("page", PAGES)
def test_the_wiki_generator_gives_the_page_a_title(page):
    """`build-wiki.py` refuses a page it has no title for."""
    src = read("scripts/build-wiki.py")
    assert f'"{page}":' in src, (
        f"{page} has no wiki title, and build-wiki.py refuses it outright: "
        f"'it would publish nowhere'"
    )


@pytest.mark.parametrize("page", PAGES)
def test_the_wiki_index_can_reach_the_page(page):
    """A title without a section publishes a page nothing links to."""
    src = read("scripts/build-wiki.py")
    # The section lists come after the title map; a page named twice is one
    # named in both.
    assert src.count(f'"{page}"') >= 2, (
        f"{page} has a wiki title but appears in no section list, so the wiki "
        f"index cannot reach it"
    )


@pytest.mark.parametrize("page", PAGES)
def test_a_reader_starting_at_the_index_can_reach_the_page(page):
    """`docs/README.md` is where a reader starts."""
    src = read("docs/README.md")
    assert f"({page})" in src, (
        f"{page} is not linked from docs/README.md, so a reader starting at "
        f"the index cannot reach it"
    )
