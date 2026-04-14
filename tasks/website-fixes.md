# Website Remaining Issues Plan

> Created: 2026-04-14
> Status: Pending

## Issue 1: Terminal Mockup Pipe Alignment

**Problem:** Terminal mockups in doc pages have pipe characters (`│`) that may not align vertically because each line wasn't manually character-counted. The monospace font fix helps but doesn't guarantee alignment if the source Markdown has inconsistent spacing.

**Fix approach:**
- Write a validation script that parses every `<pre class="terminal-body">` block from the built HTML
- Strip HTML tags, find pipe positions on each line, verify they match across lines
- For any misaligned mockup, fix the source Markdown by padding/trimming to exact column widths
- Add the validation script to CI so future changes don't break alignment

**Files:** `website/content/docs/keybindings.md` (8 mockups), `website/content/docs/theme.md` (7 mockups), `website/templates/index.html` (2 mockups)

**Effort:** 2-3 hours (script + manual fixes)

---

## Issue 2: Publish to crates.io

**Problem:** The install page says "build from source" because sipnab isn't on crates.io. `cargo install sipnab` would be the ideal user experience.

**Fix approach:**
- Verify `Cargo.toml` metadata is complete (description, license, repository, homepage, keywords, categories, readme, exclude)
- Add `exclude` patterns for test pcaps, website, tasks, and other non-essential files to keep the crate size under 1MB
- Run `cargo publish --dry-run` to validate
- Publish with `cargo publish`
- Update website: landing page install command back to `cargo install sipnab`, install page adds crates.io as primary method
- Add crates.io badge to README

**Prereqs:** Repository owner (you) needs a crates.io API token. Run `cargo login` first.

**Files:** `Cargo.toml` (metadata + exclude), `website/templates/index.html`, `website/content/docs/install.md`, `README.md`

**Effort:** 30 minutes (metadata) + your action (cargo login + publish)

---

## Issue 3: Real PNG Screenshots

**Problem:** All "screenshots" are styled `<pre>` blocks that depend on monospace fonts loading correctly. Real PNG/WebP screenshots would be font-independent and show the actual TUI pixel-perfect.

**Fix approach:**
- Use `vhs` (VHS by Charmbracelet) to record terminal GIFs/PNGs programmatically:
  ```
  # tape.vhs
  Set Shell bash
  Set FontSize 14
  Set Width 1200
  Set Height 800
  Type "sipnab -I tests/pcap-samples/SIP_CALL_RTP_G711"
  Enter
  Sleep 2s
  Screenshot screenshots/call-list.png
  Type "j"
  Sleep 500ms
  Enter
  Sleep 1s
  Screenshot screenshots/call-flow.png
  ```
- Alternatively, use `ttyd` + Playwright to render the TUI in a browser and screenshot
- Or simplest: manually run sipnab, take macOS screenshots, crop and optimize
- Store screenshots in `website/static/img/` (WebP format, ~50-100KB each)
- Replace `<pre>` mockups on the landing page with `<img>` tags
- Keep `<pre>` mockups on doc pages as fallback (they're searchable)

**Screenshots needed:**
1. Call list view (full terminal, shows multiple dialogs with state colors)
2. Call flow ladder (3-participant, Unicode arrows, auth collapse)
3. Raw message view (syntax highlighted SIP INVITE)
4. RTP streams view (quality metrics table)
5. F2 save dialog (vertical format picker)
6. F7 filter dialog
7. F8 settings dialog

**Files:** `website/static/img/` (new), `website/templates/index.html`, `website/content/docs/keybindings.md`

**Effort:** 1-2 hours (capture + optimize + integrate)

---

## Issue 4: Search Quality Validation

**Problem:** The elasticlunr search index builds correctly but search result quality hasn't been tested. Users searching for specific topics (e.g., "MOS", "retransmit", "filter method") may not find relevant results.

**Fix approach:**
- Test 10 representative search queries against the built index:
  1. "MOS" → should find RTP quality docs
  2. "retransmit" → should find filter DSL + keybindings (fold)
  3. "filter method" → should find filter DSL
  4. "theme dark" → should find theme guide
  5. "REGISTER" → should find keybindings + CLI
  6. "TLS decrypt" → should find CLI + install
  7. "save pcap" → should find keybindings + CLI
  8. "API endpoint" → should find API docs
  9. "jitter loss" → should find filter DSL + CLI
  10. "F7" → should find keybindings
- If results are poor, tune Zola's search config (boost title vs body, adjust `include_content`)
- Add a "search tips" note to the search overlay: "Try: MOS, retransmit, filter, theme"

**Files:** `website/config.toml` (search config), `website/templates/base.html` (search UI)

**Effort:** 1 hour

---

## Priority Order

1. **Issue 1 (alignment)** — users see this immediately, embarrassing
2. **Issue 3 (PNG screenshots)** — makes the site look professional vs. amateur
3. **Issue 2 (crates.io)** — improves install experience significantly
4. **Issue 4 (search)** — nice-to-have, affects repeat visitors

## Total Effort

~5-6 hours for all four issues.
