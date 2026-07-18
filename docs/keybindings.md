# Keybindings

Complete keyboard shortcut reference for sipnab's interactive TUI.

Keys marked with **(configurable)** can be remapped via the `[keybindings]` config section. See [config-reference.md](config-reference.md) for details. All other keys are hardcoded.

## Global

| Key | Action |
|-----|--------|
| Ctrl+C | Force quit |
| Ctrl+L | Clear all calls (same as F5) |
| v | Show version (with git commit) in the status line |
| n | Cycle name resolution (Off / Static / DNS) |
| N | Name the selected address (map IP → host/FQDN) |
| Mouse wheel | Scroll (every view: lists move the selection, text views scroll) |

`v` and `n` are built-in fallbacks: a key you explicitly rebind in
`[keybindings]` always wins over them.

## Call List

| Key | Action |
|-----|--------|
| Up / k | Navigate up |
| Down / j | Navigate down |
| PgUp | Page up |
| PgDn | Page down |
| Home | Jump to first dialog |
| End | Jump to last dialog |
| Enter | Open call flow for the selected dialog — with two or more starred rows, opens one chronologically merged flow of all of them |
| Space | Star/unstar dialog (`[*]`) for multi-select: F2 saves all starred dialogs, Enter opens them as one merged flow |
| Esc / q | Quit **(configurable: `quit`)** |
| < | Sort by previous column |
| > | Sort by next column |
| Z | Reverse sort direction |
| A | Toggle autoscroll **(configurable: `autoscroll`)** |
| p | Pause/resume capture **(configurable: `pause`)** |
| / | Activate search **(configurable: `search`)** — while typing, ↑/↓/PgUp/PgDn/Home/End move the highlight in the narrowed list, Space stars rows, and Enter commits the query and opens the selection in one press |
| i | Clear non-matching dialogs |
| I | Clear matching dialogs |
| t | Cycle timestamp mode (absolute / delta-prev / delta-first / scaled) |
| u | Cycle From/To column display (default / host:port / user / user@host:port) |
| r / F6 | Show raw SIP message for selected dialog |
| s | Switch to Statistics view |
| O | Open pcap file (File Open dialog) |
| F8 | Open Settings popup **(configurable: `settings`)** |
| Tab | Switch to RTP Streams view |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save capture **(configurable: `save`)** |
| F3 | Search (same as `/`) |
| F4 | Open extended multi-leg flow for the selected dialog **(configurable: `extended_flow`)** |
| F5 | Clear all calls **(configurable: `clear_calls`)** |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter **and** persisted search |
| F10 | Column selector **(configurable: `column_selector`)** |

A search committed with Enter keeps narrowing the list and is shown on the
status line as `Search: /query (F9 clears)`; F9 clears it together with any
active filter.

## Call Flow

| Key | Action |
|-----|--------|
| Tab | Switch focus between the ladder (left) and detail (right) panes |
| Up / k | Previous message — or scroll detail up when the detail pane is focused |
| Down / j | Next message — or scroll detail down when the detail pane is focused |
| PgUp | Page up (ladder, or detail when focused) |
| PgDn | Page down (ladder, or detail when focused) |
| Home | Jump to first message (or top of detail when focused) |
| End | Jump to last message (or bottom of detail when focused) |
| Enter | Open full-screen raw message view |
| Space | Select message for diff (press on two messages to compare) |
| Esc | Back to call list |
| d | Cycle SDP display mode (none / summary / full) |
| t | Cycle timestamp mode (absolute / delta-prev / delta-first / scaled) |
| c | Cycle color scheme (method / call-id / cseq) |
| h | Cycle header-name display (as captured / expanded / compact) — visual only, rewrites `From:` ↔ `f:` etc. in the message text views |
| R | Toggle detail panel visibility |
| + / = / 0 / Left | Widen the detail pane, narrowing the ladder (with the split off, shows a hint instead) |
| - / 9 / Right | Narrow the detail pane, widening the ladder (with the split off, shows a hint instead) |
| w | Toggle line wrapping in the detail pane (off = long lines truncate and a scrollbar appears along the bottom edge) |
| ← / → | Scroll the detail pane horizontally when it is focused with wrap off |
| [ | Scroll detail panel up |
| ] | Scroll detail panel down |
| e | Expand/collapse the selected fold header (retransmissions, auth retries) |
| f | Filter the ladder to the selected message's transaction (toggle) |
| a | Open combined detail for the selected message's transaction |
| A | Open combined detail for the whole dialog |
| m | Set mark at current message |
| M | Clear mark |
| E | Export Mermaid sequence diagram to clipboard |
| x / F4 | Toggle extended multi-leg flow **(configurable: `extended_flow`)** |
| r | Jump to RTP Streams view |
| N | Name endpoints (map IP → host/FQDN; Tab/Shift-Tab switch between the offered participants) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save **(configurable: `save`)** |
| F5 | Reset message-compare selection **(configurable: `clear_calls`)** |
| F6 / Ctrl+R | Toggle RTP display in flow |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter |

In the split view, `Tab` moves keyboard focus between the two panes; the
focused pane is shown in the status line (`Focus: Ladder` / `Focus: Detail`)
and gets a highlighted border. When either pane has more rows than fit, a
vertical scrollbar appears on its right edge. `[` and `]` always scroll the
detail pane regardless of focus.

## Raw Message

| Key | Action |
|-----|--------|
| Up / k | Scroll up |
| Down / j | Scroll down |
| PgUp | Page up |
| PgDn | Page down |
| Home / End | Jump to top/bottom |
| / | Search within message |
| n / N | Jump to the next / previous search-match line (wraps) |
| s | Toggle syntax highlighting |
| c | Cycle color scheme |
| h | Cycle header-name display (as captured / expanded / compact) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save **(configurable: `save`)** |
| Esc | Back to the view it was opened from (call flow or call list) |

## Message Diff

| Key | Action |
|-----|--------|
| Up / k, Down / j | Scroll |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| h | Cycle header-name display (as captured / expanded / compact) |
| q | Quit **(configurable: `quit`)** |
| Esc | Back to call flow |
| F1 / ? | Help **(configurable: `help`)** |

## Combined Detail

Opened from the call flow with `a` (transaction) or `A` (whole dialog): every
message of the selection rendered as one scrollable document.

| Key | Action |
|-----|--------|
| Up / k, Down / j | Scroll |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| h | Cycle header-name display (as captured / expanded / compact) |
| Esc | Back to call flow |

## RTP Streams

| Key | Action |
|-----|--------|
| Up / k | Navigate up |
| Down / j | Navigate down |
| PgUp / PgDn | Page scroll |
| Home | Jump to first stream |
| End | Jump to last stream |
| / | Search streams (SSRC, codec, addresses, dialog) **(configurable: `search`)** — while typing, ↑/↓/PgUp/PgDn/Home/End move the highlight in the narrowed list and Enter commits the query and opens the highlighted stream |
| Enter | Open stream detail |
| Tab | Switch to Call List |
| Esc | Back to Call List |
| N | Name the selected stream's source address (map IP → host/FQDN) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save the selected stream's audio as WAV **(configurable: `save`)** |
| F7 | Open filter dialog **(configurable: `filter`)** |

## Stream Detail

| Key | Action |
|-----|--------|
| Up / k | Scroll up |
| Down / j | Scroll down |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| Shift+P | Play / stop the stream's audio (G.711; requires the `audio` build) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save the stream's audio as WAV **(configurable: `save`)** |
| Esc | Back to RTP Streams |

## Statistics

| Key | Action |
|-----|--------|
| Up / k, Down / j | Scroll |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| Esc / q / s | Back to Call List |

## Help

| Key | Action |
|-----|--------|
| Esc / F1 / q | Close help |

## Save Popup

| Key | Action |
|-----|--------|
| Esc | Cancel and close |
| Enter | Save to the specified path |
| Tab | Cycle format forward (PCAP -> PCAP-NG -> TXT -> JSON -> NDJSON -> CSV -> Mermaid/HTML -> Markdown -> WAV -> SIPp XML -> RTP JSON) |
| Shift+Tab | Cycle format backward |
| Left / Right | Move cursor in filename |
| Home / End | Jump to start/end of filename |
| Backspace | Delete character before cursor |
| (any char) | Insert character |

Save formats: **PCAP**, **PCAP-NG**, **TXT**, **JSON**, **NDJSON**, **CSV**, **Mermaid/HTML**, **Markdown**, **WAV**, **SIPp XML**, **RTP JSON**

## Filter Popup

| Key | Action |
|-----|--------|
| Esc | Cancel without applying |
| Enter | Apply filter (or cancel if Cancel button focused) |
| Tab | Focus next field |
| Shift+Tab / BackTab | Focus previous field |
| Down | Next field (or checkbox down) |
| Up | Previous field (or checkbox up) |
| Left / Right | Move within checkboxes or text cursor |
| Space | Toggle checkbox / activate button |
| F9 | Clear all fields and active filter, close popup |
| Backspace / Delete | Text editing in focused text field |
| Home / End | Jump to start/end of text field |
| (any char) | Insert character in focused text field |

The SIP-method grid starts with an **All** master checkbox: Space on it checks
or unchecks every method at once.

## Settings Popup

| Key | Action |
|-----|--------|
| Esc | Close settings |
| Up / k | Previous setting |
| Down / j | Next setting |
| Enter / Space | Toggle or cycle the focused setting |

Settings items: Color mode, Timestamp mode, Autoscroll, Raw preview, SDP display mode, Syntax highlighting

## File Open Popup

| Key | Action |
|-----|--------|
| Esc | Cancel and close |
| Enter | Open the specified pcap file |
| Left / Right | Move cursor |
| Home / End | Jump to start/end of path |
| Backspace | Delete character before cursor |
| (any char) | Insert character |

The browser lists `.pcap`, `.pcapng`, and `.cap` files, plus their
gzip-compressed forms (`*.pcap.gz`, …), which sipnab decompresses on the fly.
If the directory can't be read — most often because sipnab was started with
`sudo` and dropped privileges to an unprivileged user that can't read your
home directory — the dialog shows the reason instead of a blank list. Run
sipnab **without** `sudo` (see [install.md](install.md) for capabilities) to
browse your own files.

## Column Selector

| Key | Action |
|-----|--------|
| Up / k | Move selection up |
| Down / j | Move selection down |
| Space | Toggle column visibility |
| s | Save the current layout to `[display] visible_columns` in your sipnabrc (persists across runs) |
| Enter / Esc | Close selector |

## Timestamp Modes

Press `t` in the Call List or Call Flow to cycle through the timestamp modes (the mode is shared across both views):

1. **Absolute** (default) -- `HH:MM:SS.mmm` wall-clock time
2. **Delta-prev** -- `+N.NNNs` time since previous entry. Color-coded in call flow:
   - Green: < 100 ms
   - Yellow: 100 ms - 1 s
   - Red: 1 s - 5 s
   - Bold red: > 5 s
3. **Delta-first** -- `+N.NNNs` cumulative time from first entry
4. **Scaled** -- delta-prev timestamps plus time-proportional spacer rows, so
   quiet gaps are visible in the ladder. The set of visible messages is
   identical in every mode — only the presentation changes.

## Name Resolution

sipnab can display host names instead of raw IP addresses (Wireshark-style),
in the call list **Source**/**Destination** columns, call-flow participant
labels, and the RTP stream views. Press **`n`** to cycle the mode (shown
briefly in the status line):

1. **Off** (default) -- raw `ip:port`
2. **Static** -- operator mappings + the system `/etc/hosts`; no network traffic
3. **DNS** -- additionally resolves via reverse DNS (PTR), looked up on a
   background worker and cached (so the UI never blocks)

Names come from three sources, highest priority first: operator-entered
mappings, then `/etc/hosts` (or a `--names` / `[names] hosts_file`), then
reverse DNS. Only the IP is substituted; the `:port` is preserved
(`sbc-edge:5060`).

To name an address **in context**, select a call-list row, stream row, or
call-flow message and press **`N`**. A popup opens pre-filled with that IP;
type a host/FQDN and press Enter (an empty name clears the mapping). Naming an
address turns resolution on automatically, and the mapping is saved to
`$XDG_CONFIG_HOME/sipnab/hosts` (`~/.config/sipnab/hosts`) so it persists
across runs.

Mappings can also be persisted into your **sipnabrc**: set
`[names] persist_to_config = true` and `N`-dialog edits are written into the
`[names.manual]` table of `~/.config/sipnab/sipnab.toml` (comments and other
sections are preserved). You can also pre-declare mappings there by hand:

```toml
[names.manual]
"192.0.2.1" = "sbc-edge"
```

When saving a capture as **PCAP-NG** with resolution active, the mappings are
embedded as a Name Resolution Block (and read back when the file is reopened).

Related flags: `--resolve` (start with resolution on), `--reverse-dns` (enable
PTR lookups; implies `--resolve`), `--names <FILE>` (preload an
`/etc/hosts`-format mapping file, repeatable). See
[cli-reference.md](cli-reference.md) and the `[names]` config section.

## See also

- [theme-guide.md](theme-guide.md) — recolor every TUI element via `[theme]`
- [config-reference.md](config-reference.md) — rebind the 11 configurable keys
  via `[keybindings]`
- [filter-dsl.md](filter-dsl.md) — the expression language the F7 filter
  dialog compiles down to (and the `--filter` flag exposes directly)
