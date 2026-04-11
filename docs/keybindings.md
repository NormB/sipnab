# Keybindings

Complete keyboard shortcut reference for sipnab's interactive TUI.

## Call List

| Key | Action |
|-----|--------|
| Up/Down, j/k | Navigate dialogs |
| PgUp/PgDn | Page scroll |
| Home/End | Jump to first/last |
| Enter | Open call flow |
| Space | Select/deselect dialog |
| Esc, q | Quit |
| < / > | Change sort column |
| Z | Reverse sort direction |
| A | Toggle autoscroll |
| p | Pause/resume capture |
| / | Search |
| i | Clear non-matching dialogs |
| I | Clear matching dialogs |
| F1 | Help |
| F2 | Save capture (PCAP/PCAP-NG/TXT) |
| F3 | Search (same as /) |
| F5 | Clear calls |
| F6 | Show raw SIP message |
| F7 | Filter dialog |
| F9 | Clear active filter |
| F10 | Column selector |
| Tab | Switch to RTP Streams |

## Call Flow

| Key | Action |
|-----|--------|
| Up/Down | Navigate messages (detail panel updates) |
| PgUp/PgDn | Page through messages |
| Home/End | First/last message |
| Enter | Full-screen raw message |
| Space | Select message for diff (press twice to compare) |
| Esc | Back to call list |
| d | Cycle SDP display (none / summary / full) |
| t | Cycle timestamps (absolute / delta-prev / delta-first) |
| c | Cycle colors (method / call-id / cseq) |
| R | Toggle detail panel |
| 9/0, +/- | Resize ladder/detail split |
| [ / ] | Scroll detail panel |
| F2 | Save |
| F4, x | Extended multi-leg flow |
| F6 | Toggle RTP display |

### Timestamp Modes

Press `t` to cycle through three timestamp modes:

1. **Absolute** (default) -- `HH:MM:SS.mmm` wall-clock time
2. **Delta-prev** -- `+N.NNNs` time since previous message, color-coded:
   - Green: <100ms
   - Yellow: 100ms-1s
   - Red: 1s-5s
   - Bold red: >5s
3. **Delta-first** -- `+N.NNNs` cumulative time from first message

## Raw Message

| Key | Action |
|-----|--------|
| Up/Down | Scroll |
| PgUp/PgDn | Page scroll |
| / | Search in message |
| s | Toggle syntax highlighting |
| c | Cycle colors |
| Esc | Back to call flow |

## RTP Streams

| Key | Action |
|-----|--------|
| Up/Down | Navigate streams |
| Tab | Switch to Call List |
| F1 | Help |
| F7 | Filter |
| Esc | Back to Call List |
