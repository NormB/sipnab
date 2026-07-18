# Website Remaining Issues Plan

> Created: 2026-04-14 · **Reconciled: 2026-07-18** (post July site overhaul +
> PR #142). Original effort estimates removed; per-issue status below.

## Issue 1: Terminal Mockup Pipe Alignment — RESOLVED

The specific misaligned mockups (keybindings call-flow ladder, Save/Settings
dialogs) were rebuilt to exact column widths in PR #142. The CI validation
script this issue asked for now exists as `tests/mockup_alignment_test.rs`:
it extracts every `<pre class="terminal-body">` block from the website
sources, strips tags/entities, and enforces box-outline and ladder-lifeline
alignment by display column (Unicode-width aware). Runs in the normal
`cargo test` CI lane. The `theme.md` mockups this plan listed no longer
exist — the July overhaul replaced them with `toml` theme-definition blocks.

## Issue 2: Publish to crates.io — DEFERRED (owner action)

Blocked on the owner's `cargo login` token; explicitly deferred. The metadata
prep steps remain valid when picked up.

## Issue 3: Real PNG Screenshots — SUPERSEDED

The July 2026 site overhaul kept the styled `<pre>` mockups deliberately
(searchable, theme-consistent) and added animated demo GIFs
(`website/static/demos/`), which cover the "show the real TUI" goal.
Revisit only if a decision is made to replace mockups with static PNGs;
the VHS capture recipe in the git history of this file is a good start.

## Issue 4: Search Quality Validation — DONE (2026-07-18)

Built the site with zola 0.19.2 and replayed the shipped elasticlunr index
under node with the 10 representative queries from this plan (MOS,
retransmit, filter method, theme dark, REGISTER, TLS decrypt, save pcap,
API endpoint, jitter loss, F7). All 10 return relevant top-3 results —
no search-config tuning needed. Replay harness: session scratchpad
`search_check.js` (trivial to recreate: `elasticlunr.Index.load` +
`idx.search(q, {bool:'OR', expand:true})`).
