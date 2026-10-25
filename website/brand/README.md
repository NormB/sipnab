# The sipnab logo

The mark is a SIP call ladder: two amber rails, a request and its response,
on the site's dark tile. It is the diagram sipnab draws for every call,
reduced to one exchange. It was drawn for this project on a 32-unit grid.
The wordmark is JetBrains Mono Bold (SIL Open Font License 1.1) turned to
outlines, so no font is embedded.

| File | Use |
|---|---|
| `mark.svg` | The source. Every other file is drawn from it by `scripts/build-icons.py`. |
| `lockup-light.svg`, `lockup-dark.svg` | The mark and the name, for light and dark backgrounds. |
| `social-preview.png` | The repository's social preview, 1280 by 640. |

The site's `favicon.svg`, `favicon.ico`, `apple-touch-icon.png` and
`og-image.png` in `website/static/` are drawn by the same script, and so is
the mark on the social card, `website/og-image.svg`. After changing
`mark.svg`, run `python3 scripts/build-icons.py`; `--check` says whether any
file is out of date. It needs `resvg`, the Python `fontTools` package, and
JetBrains Mono and Inter installed where `fc-match` finds them.

## Use of the name and logo

These files are not covered by the code's MIT or Apache-2.0 license. You may
use the name and the logo, unchanged, to refer to the sipnab project, for
example in an article, a talk or a list of integrations. Do not use them in a
way that suggests your product is sipnab or is endorsed by it, and do not
change them.
