# sipnab.com — website source

Static site for [sipnab.com](https://sipnab.com), built with
[Zola](https://www.getzola.org/).

## Local preview

```bash
# Run all of these, in order.
cd website
zola serve
```

Open <http://127.0.0.1:1111>. Live-reload on save.

## Build

```bash
# Run all of these, in order.
cd website
zola build
```

Output goes to `website/public/`, which `.gitignore` excludes. Every
build regenerates it, so a stale copy on disk describes whatever was
last built locally rather than what the site serves.

## Deploy

`.github/workflows/pages.yml` builds and publishes sipnab.com on every
push to `main` that touches a path it watches. It builds the WASM
analyzer with `wasm-pack`, checks the exported symbols, runs
`zola build`, deploys to GitHub Pages, and then refreshes the
Cloudflare CSP hashes against the artifact it just published.

That last step is why an inline `<script>` edit is not finished when
the deploy goes green: the hash refresh runs AFTER the upload, so the
changed script is blocked for the window between the two. Load the
deployed page before calling such a change done.

`scripts/deploy-website.sh` is the alternative for anyone self-hosting
a copy — it builds, rsyncs and chowns to a host over SSH. It is not
how sipnab.com ships.

```bash
DEPLOY_HOST=user@web-host scripts/deploy-website.sh
```

See the comment block at the top of that script for the full env-var
contract (`DEPLOY_PATH`, `DEPLOY_OWNER`, `ZOLA_BIN`, `SKIP_BUILD`).

## Layout

```text
website/
├── config.toml             # Zola config (base_url, [extra] vars, search index)
├── content/                # Markdown source
│   ├── _index.md           # Homepage front-matter (body in templates/index.html)
│   ├── analyze/            # Browser pcap-analysis page
│   └── docs/               # CLI / API / Filter DSL / MCP / Theme / etc.
├── templates/              # Tera HTML templates
│   ├── base.html
│   ├── index.html          # Homepage body (hero, features, stats)
│   ├── page.html           # Single-doc layout
│   ├── section.html        # Section index
│   └── 404.html
├── sass/                   # Compiled to public/css/ on build
├── static/                 # Verbatim assets
└── public/                 # Generated output. `.gitignore` excludes it; every build regenerates it
```

## Regenerating the animated demos

The homepage demo tabs are WebP animations rendered with [VHS](https://github.com/charmbracelet/vhs)
from tape scripts in `../demos/`. Every tape `Source`s `demos/common.tape`
for a single shared look (theme, font, size), so styling lives in one place.

Rendering needs `vhs`, `ttyd` and `ffmpeg` on `PATH`, plus an installed
`sipnab` (0.5.x). To render every demo plus the hero still into
`static/demos/`:

```sh
make -C demos
```

To re-render a single demo — much faster when you are iterating on one tape:

```sh
make -C demos 09-detail.webp
```

Run from the repo root so tapes resolve `tests/pcap-samples/*`. Outputs land
in `static/demos/`. After re-rendering, bump the `?v=N` query on the affected
`<img>`/hero in `templates/index.html` to bust the CDN cache.

Notes:
- VHS cannot send function keys (F2/F7/F10…) or `Escape`-prefixed sequences
  cleanly, so demos use letter/arrow/`Ctrl` keys only (the TUI treats `Esc`
  as quit). F-key-only flows (Save dialog, Filter dialog, Column selector)
  are intentionally not demoed.
- GIF is only an intermediate. VHS emits one, `demos/Makefile` converts it to
  WebP and deletes the GIF in the same recipe, so nothing under
  `static/demos/` is a GIF and none ever reaches a visitor.

## Updating the test count

The "Engineered for Production" stats panel on the homepage shows an
automated-test count that the pre-commit hook validates against the
actual `cargo test --features full` output. If the hook complains
about the count being stale, edit the `data-count="…"` attribute in
`templates/index.html` and the prose number in the "Built in Rust"
feature row to match `cargo test --features full | grep "test result:"
| awk '{sum+=$4} END {print sum}'`.
