# Docs & sipnab.com Improvements — Synthesis & Plan

> Created 2026-07-18. Source: three parallel audits (repo docs vs 0.5.14 code;
> website tree; live sipnab.com). crates.io publish explicitly **out of scope**
> (deferred by owner). Attribution/credit "gaps" not applicable.

## External / owner action (cannot fix in repo)

- **Cloudflare Email Address Obfuscation** is rewriting `user@host` strings
  inside code blocks and terminal mockups on the live site (e.g.
  `bob@10.0.0.2`, `12013223@200.57.7.195`, `7f3a9c@10.0.0.5` →
  `[email protected]` + a `/cdn-cgi/l/email-protection` link that itself 404s).
  No real emails exist in page bodies. **Fix: disable Scrape Shield → Email
  Address Obfuscation for the sipnab.com zone** in the Cloudflare dashboard.

## Tier A — PII / correctness (implement first)

1. **[P1] `10.0.0.40:5060` "(OpenSIPS proxy)"** — real LAN IP+role of this host,
   only in `website/content/docs/keybindings.md:315` (source-of-truth
   `docs/keybindings.md` is clean). Replace with a synthetic address.
2. **[P1] `thor-02` hostname** — personal lab host, in BOTH
   `docs/benchmarks.md:16` and `website/content/docs/benchmarks.md:23`. Replace
   with generic descriptor.
3. **[P2] `-x/--quiet-bad-parse` + `--proto-number` missing** from
   `docs/cli-reference.md` (both exist in `src/cli.rs`, both tested).
4. **[P2] "30 fields" → "31 fields"** in `website/templates/index.html:150`
   (`FIELD_NAMES` has 31).
5. **[P2] 7 config keys missing** from `website/content/docs/config.md`:
   `capture.promisc`, `sip.xcid_headers`, `[crash]`
   reports/backtrace/report_dir/core, keybinding `settings`. Mirror
   `docs/config-reference.md`.
6. **[P2] Homepage perf stats lack provenance** — "11.4× sngrep" / "2.5M pkts/s"
   (`index.html:221,225`) were measured on 0.4.16. Add "(v0.4.16)" provenance to
   the stat labels (re-benchmark on 0.5.x deferred as separate work).

## Tier B — polish

7. **[P3] mockup alignment** — `website/content/docs/keybindings.md` blocks at
   L315 (ladder), L432 (save dialog), L458 (settings dialog) are measurably
   misaligned. Rebuild to exact column widths.
8. **[P3] HEP send wording** — `docs/install.md:175` "HEP v2/v3 send" → "v3 send
   + v2/v3 receive" (sender is v3-only; matches README).
9. **[P3] feature-gated flag list** — `docs/cli-reference.md:238` omits
   `mcp`/`mcp-http`.
10. **[P3] man page timestamp modes** — `man/sipnab.1:141` lists 3, code has 4
    (add `scaled`).
11. **[P3] favicon.ico 404** — add a static `/favicon.ico` (pages use inline SVG;
    classic fallback 404s).
12. **[P3] untrack `website/public/`** (34 stale tracked files, badge shows
    v0.4.1) + add to `.gitignore` (convention: don't hand-commit built site).
13. **[P3] test-count prose gate** — `index.html:158` "2516 automated tests"
    prose is ungated; can diverge from `data-count`. Harden `.githooks/pre-commit`
    gate 5 (anchor to the tests stat, cover the prose figure).
14. **[P3] stragglers** — commit-hash `(c9620a5f)` in `website/.../install.md:347`
    → `<hash>` placeholder; remove 2 unreferenced demo GIFs
    (`05-file-open.gif`, `06-rtp-quality.gif`); `-1` duplicate-slug anchor
    fragility in output-formats.md/mcp.md (low, optional).

## Deferred (not this pass)

- Re-benchmark on 0.5.x (Tier A #6 adds provenance instead).
- Search 10-query quality validation (zola not installed on this box).
- Full RFC 5737 sweep of all example IPs (large churn, only .40 was real).
- crates.io publish (owner deferred).

## Test/gate notes

- Doc changes are non-behavioral; `docs_drift_test.rs` gates `--flag` existence
  (safe to add documented flags that exist), version markers, and MCP examples.
- `keybinding_drift_test.rs` does not read config.md — config-key additions safe.
- Gate hardening (#13) IS a tooling behavior change → verify the hook before/after.
- No commit/push without explicit approval (standing rule).
