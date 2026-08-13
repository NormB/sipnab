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

Output goes to `website/public/`. The repo tracks `public/` so the
deploy step has a stable artifact to push.

## Deploy

The site is rsync'd to a static-hosting host. There's no GitHub
Actions automation — the deploy runs from a developer machine with
SSH access to the deploy target.

```bash
DEPLOY_HOST=user@web-host scripts/deploy-website.sh
```

The script builds, rsyncs, and chowns. See the comment block at the
top of `scripts/deploy-website.sh` for the full env-var contract
(`DEPLOY_PATH`, `DEPLOY_OWNER`, `ZOLA_BIN`, `SKIP_BUILD`).

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
└── public/                 # Generated output (committed for deploy stability)
```

## Regenerating the animated demos

The homepage demo tabs are GIFs rendered with [VHS](https://github.com/charmbracelet/vhs)
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
make -C demos 09-detail.gif
```

Run from the repo root so tapes resolve `tests/pcap-samples/*`. Outputs land
in `static/demos/`. After re-rendering, bump the `?v=N` query on the affected
`<img>`/hero in `templates/index.html` to bust the CDN cache.

Notes:
- VHS cannot send function keys (F2/F7/F10…) or `Escape`-prefixed sequences
  cleanly, so demos use letter/arrow/`Ctrl` keys only (the TUI treats `Esc`
  as quit). F-key-only flows (Save dialog, Filter dialog, Column selector)
  are intentionally not demoed.
- If `gifsicle` is installed, `gifsicle -O3 --lossy=40` shrinks the larger
  GIFs (notably the CLI demo) further; it is not required.

## Updating the test count

The "Engineered for Production" stats panel on the homepage shows an
automated-test count that the pre-commit hook validates against the
actual `cargo test --features full` output. If the hook complains
about the count being stale, edit the `data-count="…"` attribute in
`templates/index.html` and the prose number in the "Built in Rust"
feature row to match `cargo test --features full | grep "test result:"
| awk '{sum+=$4} END {print sum}'`.
