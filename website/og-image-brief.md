# Brief: social-card image for sipnab.com

Create a **1200 × 630 px PNG** Open Graph image (`og-image.png`). It is the
preview card shown when `https://www.sipnab.com` is shared on X/Twitter,
LinkedIn, Slack, Discord, and chat apps. It must look crisp full-size and
remain legible scaled down to ~400 px wide, including with corners cropped
to a rounded-rect by some platforms.

## What sipnab is (context for the design)

sipnab is an open-source SIP & RTP (VoIP) capture and analysis tool —
think "sngrep + sipgrep, rebuilt in Rust": an interactive terminal UI,
a CLI, a REST API, and an in-browser WebAssembly analyzer. The audience
is VoIP/telecom engineers and SREs who live in terminals. The aesthetic
of the whole brand is "beautiful terminal", not "corporate SaaS".

## Brand tokens (use these exactly)

| Token | Hex | Use |
|---|---|---|
| Background | `#0a0e14` | the canvas — near-black blue (ayu-dark) |
| Surface | `#1f2430` | optional panel/card behind elements |
| Border | `#2d3640` | hairline rules, panel borders |
| Text | `#cbccc6` | primary copy |
| Dimmed text | `#707a8c` | secondary copy |
| **Accent (amber)** | `#ffcc66` | the brand color — wordmark, highlights |
| Link blue | `#73d0ff` | a second accent, sparingly |
| Green | `#bae67e` | success/200-OK touches, sparingly |
| Red | `#ff6666` | error/failure touches, sparingly |

Fonts: **JetBrains Mono** for the wordmark and any code/terminal text;
**Inter** for the tagline. If exact fonts are unavailable, any clean
monospace + neutral sans is acceptable, but monospace must dominate.

Logo mark: a rounded square (radius ≈ 12%) filled `#ffcc66` containing a
bold lowercase monospace "s" in `#0a0e14` — this is the site favicon and
may be reproduced at small size, but the full wordmark matters more.

## Required content

1. Wordmark: `sipnab` — lowercase, JetBrains Mono bold, `#ffcc66`,
   the dominant element.
2. Tagline (Inter, `#cbccc6`):
   **The SIP & RTP analysis tool for people who ship voice infrastructure.**
3. One supporting line (Inter or mono, `#707a8c`):
   **One binary. Terminal UI · CLI · REST API · WebAssembly. Built in Rust.**
4. Domain, small, bottom corner (mono, `#707a8c`): `sipnab.com`

Do NOT include: version numbers, GitHub octocat/logos (trademark),
screenshots with unreadable micro-text, stock-photo imagery, gradients
that fight the flat terminal aesthetic.

## Visual motif (the part that makes it good)

The signature visual of SIP analysis is the **call-flow ladder diagram**:
two or three vertical lifelines with horizontal labeled arrows between
them. Render a stylized, simplified ladder as the right-hand third or as
a subtle background panel, for example:

```
 10.0.0.1                 10.0.0.2
    │      INVITE ──────────▶ │
    │ ◀────────── 180 Ringing │
    │ ◀────────── 200 OK      │
    │      ACK ──────────────▶│
    │  ═══════ RTP  ═════════ │
```

Style it like the TUI renders it: thin `#2d3640`/`#707a8c` lifelines,
arrows and labels in mono; color the `200 OK` green (`#bae67e`), keep
`INVITE`/`ACK` amber or text-gray, and render the RTP stream as a
thicker amber double-line. Labels may be small — the ladder reads as a
shape even when text is too small; it must merely *be* a real, correct
SIP flow (INVITE → 180 → 200 → ACK → RTP), because the audience will
zoom in.

Optionally frame the whole composition as a terminal window: a `#1f2430`
title bar with three dim window dots and a 1px `#2d3640` border, on the
`#0a0e14` canvas with generous outer margin.

## Layout guidance

- Left two-thirds: wordmark large (~120–140 px cap height), tagline
  under it, supporting line under that, generous line spacing.
- Right third (or full-bleed background at low contrast): the ladder
  motif.
- Keep all text inside a 1120 × 550 px safe area centered on the canvas
  (platforms crop edges and round corners).
- Flat colors, no drop shadows heavier than a subtle 1px border, no
  more than the listed palette.
- Contrast check: tagline must remain readable at 25% scale.

## Deliverable

- `og-image.png`, exactly 1200 × 630, sRGB, under 300 KB
  (flat colors compress well; use indexed/palette PNG if needed).
- If you can, also emit the source as SVG so it can be regenerated.

It will be installed at `website/static/og-image.png` and referenced as
`<meta property="og:image" content="https://www.sipnab.com/og-image.png">`
plus `twitter:card=summary_large_image`.
