# Keybindings

Complete keyboard shortcut reference for sipnab's interactive TUI.

Keys marked with **(configurable)** can be remapped via the `[keybindings]` config section. See [config-reference.md](config-reference.md) for details. All other keys are hardcoded.

## Global

| Key | Action |
|-----|--------|
| Ctrl+C | Force quit |
| Ctrl+L | Redraw screen |

## Call List

| Key | Action |
|-----|--------|
| Up / k | Navigate up |
| Down / j | Navigate down |
| PgUp | Page up |
| PgDn | Page down |
| Home | Jump to first dialog |
| End | Jump to last dialog |
| Enter | Open call flow for selected dialog |
| Space | Select/deselect dialog (for multi-select save) |
| Esc / q | Quit **(configurable: `quit`)** |
| < | Sort by previous column |
| > | Sort by next column |
| Z | Reverse sort direction |
| A | Toggle autoscroll **(configurable: `autoscroll`)** |
| p | Pause/resume capture **(configurable: `pause`)** |
| / | Activate search **(configurable: `search`)** |
| i | Clear non-matching dialogs |
| I | Clear matching dialogs |
| t | Cycle timestamp mode (absolute / delta-prev / delta-first) |
| r / F6 | Show raw SIP message for selected dialog |
| s | Switch to Statistics view |
| O | Open pcap file (File Open dialog) |
| Tab | Switch to RTP Streams view |
| F1 | Help **(configurable: `help`)** |
| F2 | Save capture **(configurable: `save`)** |
| F3 | Search (same as `/`) |
| F5 | Clear all calls **(configurable: `clear_calls`)** |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter |
| F10 | Column selector **(configurable: `column_selector`)** |

## Call Flow

| Key | Action |
|-----|--------|
| Up / k | Navigate to previous message (detail panel updates) |
| Down / j | Navigate to next message |
| PgUp | Page up through messages |
| PgDn | Page down through messages |
| Home | Jump to first message |
| End | Jump to last message |
| Enter | Open full-screen raw message view |
| Space | Select message for diff (press on two messages to compare) |
| Esc | Back to call list |
| d | Cycle SDP display mode (none / summary / full) |
| t | Cycle timestamp mode (absolute / delta-prev / delta-first) |
| c | Cycle color scheme (method / call-id / cseq) |
| R | Toggle detail panel visibility |
| 0 / + / = / Right | Increase ladder panel width |
| 9 / - / Left | Decrease ladder panel width |
| [ | Scroll detail panel up |
| ] | Scroll detail panel down |
| e | Toggle fold/expand for selected message |
| m | Set mark at current message |
| M | Clear mark |
| E | Export Mermaid sequence diagram to clipboard |
| x / F4 | Toggle extended multi-leg flow **(configurable: `extended_flow`)** |
| F1 | Help **(configurable: `help`)** |
| F2 | Save **(configurable: `save`)** |
| F5 | Start compare mode **(configurable: `clear_calls`)** |
| F6 | Toggle RTP display in flow |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter |

## Raw Message

| Key | Action |
|-----|--------|
| Up / k | Scroll up |
| Down / j | Scroll down |
| PgUp | Page up |
| PgDn | Page down |
| Home | Scroll to top |
| / | Search within message |
| s | Toggle syntax highlighting |
| c | Cycle color scheme |
| Esc | Back to call flow |

## Message Diff

| Key | Action |
|-----|--------|
| q | Quit |
| Esc | Back to call flow |
| F1 | Help |

## RTP Streams

| Key | Action |
|-----|--------|
| Up / k | Navigate up |
| Down / j | Navigate down |
| Home | Jump to first stream |
| End | Jump to last stream |
| Tab | Switch to Call List |
| Esc | Back to Call List |
| F1 | Help **(configurable: `help`)** |
| F7 | Open filter dialog **(configurable: `filter`)** |

## Statistics

| Key | Action |
|-----|--------|
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
| Tab | Cycle format forward (PCAP -> PCAP-NG -> TXT -> Mermaid) |
| Shift+Tab | Cycle format backward |
| Left / Right | Move cursor in filename |
| Home / End | Jump to start/end of filename |
| Backspace | Delete character before cursor |
| (any char) | Insert character |

Save formats: **PCAP**, **PCAP-NG**, **TXT**, **Mermaid**

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

## Column Selector

| Key | Action |
|-----|--------|
| Up / k | Move selection up |
| Down / j | Move selection down |
| Space | Toggle column visibility |
| Enter / Esc | Close selector |

## Timestamp Modes

Press `t` in the Call List or Call Flow to cycle through three timestamp modes (the mode is shared across both views):

1. **Absolute** (default) -- `HH:MM:SS.mmm` wall-clock time
2. **Delta-prev** -- `+N.NNNs` time since previous entry. Color-coded in call flow:
   - Green: < 100 ms
   - Yellow: 100 ms - 1 s
   - Red: 1 s - 5 s
   - Bold red: > 5 s
3. **Delta-first** -- `+N.NNNs` cumulative time from first entry
