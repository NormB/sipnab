# Keybindings

Complete keyboard shortcut reference for sipnab's interactive TUI.

You can remap keys marked **(configurable)** in the `[keybindings]` config section. See [config-reference.md](config-reference.md) for details. All other keys are hardcoded.

Annotated screenshots of every view are in the [TUI visual tour](#tui-views) at the bottom of this page.

## Essential keys

> **Quick start:** `j`/`k` for vim-style up/down, `Enter` to drill into a call, `Esc` to go back, `Tab` to switch between Call List and RTP Streams.

| Key | Action | Views |
|-----|--------|-------|
| `j` / `k` | Navigate down / up | All list and scroll views |
| `Enter` | Drill in (call flow, raw message, stream detail) | Call List, Call Flow, RTP Streams |
| `Esc` | Back to the previous view (quits from the Call List) | All views |
| `Tab` | Switch between Call List and RTP Streams | Call List, RTP Streams |
| `/` | Search | Call List, Raw Message, RTP Streams |
| `F7` | Open filter dialog | Call List, Call Flow, RTP Streams |
| `F2` | Save capture (or the selected stream's audio) | Call List, Call Flow, Raw Message, RTP Streams, Stream Detail |
| `Space` | Star dialogs for multi-select — save them, or open them as one merged flow | Call List |
| `t` | Cycle timestamp mode | Call List, Call Flow |
| `F1` | Help | Call List, Call Flow, Raw Message, Message Diff, Combined Detail, RTP Streams, Stream Detail |

## Global

| Key | Action |
|-----|--------|
| Ctrl+C | Force quit |
| Ctrl+L | Clear calls (same as F5) |
| v | Show version (with git commit) in the status line |
| n | Cycle name resolution (Off / Static / DNS) |
| N | Name the selected address (map IP → host/FQDN) |
| F12 | Toggle mouse capture — off enables the terminal's native drag-to-select (wheel scrolling pauses until re-enabled) |
| Mouse wheel | Scroll (every view: lists move the selection, text views scroll) |

`v`, `n`, and `F12` ship as fallbacks: a key you explicitly rebind in
`[keybindings]` always wins over them. In the Raw Message view with an active
search, `n`/`N` are match navigation instead.

## Copying text

Clipboard copies (`y` in the Raw Message view, `E` in the Call Flow view) use
**OSC 52**, an escape sequence the terminal maps to your system clipboard. It
travels in-band over the pty, so it works across SSH with no X11 forwarding —
your terminal must support it, and most modern ones (kitty, WezTerm, iTerm2,
Windows Terminal, foot, recent xterm) do. On top of OSC 52, sipnab also feeds
`pbcopy`/`xclip` silently when one is available. Copies stop at 72 KiB
(terminals limit OSC 52 payloads); the status line reports how much it copied.

To select arbitrary screen text with the mouse, press `F12` to turn mouse
capture off and drag as usual, then `F12` again to get wheel scrolling back.
In many terminals holding **Shift** while dragging bypasses mouse capture
without toggling anything.

## Call list

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
| D | Open the Quality Dashboard (live MOS/jitter/loss) |
| T | Open the call timeline for the selected dialog (Esc / q closes it) |
| O | Open pcap file (File Open dialog) |
| F8 | Open Settings popup **(configurable: `settings`)** |
| Tab | Switch to RTP Streams view |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save capture **(configurable: `save`)** |
| F3 | Search (same as `/`) — matches Call-ID, method, From/To user, addresses, dialog state, and the full raw message text (headers and bodies, including SDP and multipart payloads) |
| F4 | Open extended multi-leg flow for the selected dialog **(configurable: `extended_flow`)** |
| F5 | Clear calls **(configurable: `clear_calls`)** — the starred dialogs when any carry a star, otherwise all of them |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter **and** persisted search |
| F10 | Column selector **(configurable: `column_selector`)** — a popup to show/hide any of the eleven Call List columns (#, Method, From, To, Source, Destination, State, Msgs, Date, PDD, Duration) |

A search committed with Enter keeps narrowing the list and appears on the
status line as `Search: /query (F9 clears)`; F9 clears it together with any
active filter.

> **Gotcha:** the `clear_calls` action binds `F5` in *both* views — in the Call List it clears calls, in the Call Flow it resets a pending message-compare selection. Rebinding `clear_calls` moves both.

## Call flow

| Key | Action |
|-----|--------|
| Tab | Switch focus between the ladder (left) and detail (right) panes |
| Up / k | Previous message or RTP bar — or scroll detail up when the detail pane has focus |
| Down / j | Next message or RTP bar — or scroll detail down when the detail pane has focus |
| PgUp | Page up (ladder, or detail when focused) |
| PgDn | Page down (ladder, or detail when focused) |
| Home | Jump to first message (or top of detail when focused) |
| End | Jump to last message (or bottom of detail when focused) |
| Enter | Open full-screen raw message view — or, with the cursor on an RTP bar, the Stream Detail view (MOS, jitter, quality intervals, burst/gap analysis, silence detection, sparklines) |
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
| ← / → | Scroll the detail pane horizontally when it has focus with wrap off |
| \[ | Scroll detail panel up |
| \] | Scroll detail panel down |
| e | Expand/collapse the selected fold header (retransmissions, auth retries) |
| f | Filter the ladder to the selected message's transaction (toggle) |
| a | Open combined detail for the selected message's transaction |
| A | Open combined detail for the whole dialog |
| m | Set mark at current message — navigate to another message and sipnab shows the **delta** between the mark and the cursor, for measuring the delay between two specific SIP messages |
| M | Clear mark |
| E | Export Mermaid sequence diagram to clipboard |
| x / F4 | Toggle extended multi-leg flow **(configurable: `extended_flow`)** — shows related B2BUA/SBC call legs together, for tracing a call through proxies and back-to-back user agents |
| r | Jump to RTP Streams view |
| N | Name endpoints (map IP → host/FQDN; Tab/Shift-Tab switch between the offered participants) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save **(configurable: `save`)** |
| F5 | Reset message-compare selection **(configurable: `clear_calls`)** |
| F6 / Ctrl+R | Toggle RTP display in flow (`Ctrl+R` is an alias for front-ends that cannot send F-keys) |
| F7 | Open filter dialog **(configurable: `filter`)** |
| F9 | Clear active filter **and** persisted search |

In the split view, `Tab` moves keyboard focus between the two panes; the
status line names the focused pane (`Focus: Ladder` / `Focus: Detail`)
and gets a highlighted border. When either pane has more rows than fit, a
vertical scrollbar appears on its right edge. `[` and `]` always scroll the
detail pane regardless of focus.

## Raw message

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
| y | Copy the displayed message's raw text to the clipboard (OSC 52, works over SSH — see [Copying text](#copying-text)) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save **(configurable: `save`)** |
| Esc | Back to the view you came from (call flow or call list) |

## Message diff

| Key | Action |
|-----|--------|
| Up / k, Down / j | Scroll |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| h | Cycle header-name display (as captured / expanded / compact) |
| q | Quit **(configurable: `quit`)** |
| Esc | Back to call flow |
| F1 / ? | Help **(configurable: `help`)** |

## Combined detail

Opened from the call flow with `a` (transaction) or `A` (whole dialog): every
message of the selection rendered as one scrollable document.

| Key | Action |
|-----|--------|
| Up / k, Down / j | Scroll |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| h | Cycle header-name display (as captured / expanded / compact) |
| F1 / ? | Help **(configurable: `help`)** |
| Esc | Back to call flow |

## RTP streams

| Key | Action |
|-----|--------|
| Up / k | Navigate up |
| Down / j | Navigate down |
| PgUp / PgDn | Page scroll |
| Home | Jump to first stream |
| End | Jump to last stream |
| / | Search streams (SSRC, codec, addresses, dialog) **(configurable: `search`)** — while typing, ↑/↓/PgUp/PgDn/Home/End move the highlight in the narrowed list and Enter commits the query and opens the highlighted stream |
| Enter | Open the Stream Detail view for the selected stream |
| D | Open the Quality Dashboard (live MOS/jitter/loss) |
| Tab | Switch to Call List |
| Esc | Back to Call List |
| N | Name the selected stream's source address (map IP → host/FQDN) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save the selected stream's audio as WAV **(configurable: `save`)** |
| F7 | Open filter dialog **(configurable: `filter`)** |

## Stream detail

| Key | Action |
|-----|--------|
| Up / k | Scroll up |
| Down / j | Scroll down |
| PgUp / PgDn | Page scroll |
| Home / End | Jump to top/bottom |
| Shift+P | Play / stop the stream's audio (G.711; requires the `audio` build) |
| L | Open the packet loss map (RTP loss pattern) |
| F1 / ? | Help **(configurable: `help`)** |
| F2 | Save the stream's audio as WAV **(configurable: `save`)** |
| Esc | Back to the view you came from (RTP Streams, Call Flow, or Quality Dashboard) |

The Stream Detail view shows comprehensive per-stream quality data: MOS score, jitter statistics, quality intervals, burst/gap analysis (RFC 3611), silence detection, and sparkline graphs for MOS and jitter trends over the stream's lifetime.

## Quality dashboard

Live call-quality overview: aggregate MOS/jitter/loss with the worst
streams ranked first and per-stream trend sparklines. Open with `D` from
the Call List or RTP Streams view.

| Key | Action |
|-----|--------|
| Up / k, Down / j | Select stream (worst first) |
| PgUp / PgDn | Page through streams |
| Home / End | Jump to best/worst |
| Enter | Open stream detail for the selection |
| L | Open the packet loss map (RTP loss pattern) for the selection |
| Esc / q / D | Close (returns to the opening view) |

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

## Save popup

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

## Filter popup

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

## Settings popup

| Key | Action |
|-----|--------|
| Esc | Close settings |
| Up / k | Previous setting |
| Down / j | Next setting |
| Enter / Space | Toggle or cycle the focused setting |

Settings items: Color mode, Timestamp mode, Autoscroll, Raw preview, SDP display mode, Syntax highlighting

## File open popup

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
If sipnab cannot read the directory — most often because it started with
`sudo` and dropped privileges to an unprivileged user that can't read your
home directory — the dialog shows the reason instead of a blank list. Run
sipnab **without** `sudo` (see [install.md](install.md) for capabilities) to
browse your own files.

## Column selector

| Key | Action |
|-----|--------|
| Up / k | Move selection up |
| Down / j | Move selection down |
| Space | Toggle column visibility |
| s | Save the current layout to `[display] visible_columns` in your sipnabrc (persists across runs) |
| Enter / Esc | Close selector |

## Timestamp modes

Press `t` in the Call List or Call Flow to cycle through the timestamp modes (both views share the mode):

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Timestamp Modes Comparison</span>
</div>
<pre class="terminal-body"><span class="t-header">Absolute:</span>           <span class="t-header">Delta-prev:</span>          <span class="t-header">Delta-first:</span>
14:23:01.000  INVITE  +0.000s  INVITE      +0.000s  INVITE
14:23:01.003  100     <span class="t-good">+0.003s</span>  100         +0.003s  100
14:23:01.847  180     <span class="t-warn">+0.844s</span>  180         +0.847s  180
14:23:03.134  200     <span class="t-bad">+1.287s</span>  200         +2.134s  200
14:23:03.137  ACK     <span class="t-good">+0.003s</span>  ACK         +2.137s  ACK
14:24:08.320  BYE     <span class="t-bad">+65.18s</span>  BYE         +67.32s  BYE</pre>
</div>

> **Tip:** Delta-prev mode is ideal for spotting latency spikes in call setup. Delta-first mode is useful for measuring total elapsed time from the first message.

## Name resolution

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
reverse DNS. Substitution touches only the IP; the `:port` stays
(`sbc-edge:5060`).

To name an address **in context**, select a call-list row, stream row, or
call-flow message and press **`N`**. A popup opens pre-filled with that IP;
type a host/FQDN and press Enter (an empty name clears the mapping). Naming an
address turns resolution on automatically, and sipnab saves the mapping to
`$XDG_CONFIG_HOME/sipnab/hosts` (`~/.config/sipnab/hosts`) so it persists
across runs.

Mappings can also persist into your **sipnabrc**: set
`[names] persist_to_config = true` and `N`-dialog edits land in the
`[names.manual]` table of `~/.config/sipnab/sipnab.toml`, leaving comments and
other sections intact. You can also pre-declare mappings there by hand:

```toml
[names.manual]
"192.0.2.1" = "sbc-edge"
```

When saving a capture as **PCAP-NG** with resolution active, sipnab embeds the
mappings as a Name Resolution Block, and reads them back when you reopen the file.

Related flags: `--resolve` (start with resolution on), `--reverse-dns` (enable
PTR lookups; implies `--resolve`), `--names <FILE>` (preload an
`/etc/hosts`-format mapping file, repeatable). See
[cli-reference.md](cli-reference.md) and the `[names]` section of
[config-reference.md](config-reference.md).

---

## TUI views

### Call list view

The call list is the main view when sipnab starts. It shows all tracked SIP dialogs with their state, timing, and quality metrics.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Call List</span>
</div>
<pre class="terminal-body"><span class="t-header"> Current Mode: Online (eth0)   Dialogs: 47 (47 displayed)  [A]</span>
<span class="t-muted"> Match Expression:             BPF Filter: port 5060</span>
<span class="t-muted"> Time: Delta-prev</span>
<span class="t-muted">  #  Method     From           To             Src IP         Dst IP         State        Msgs  Date        PDD</span>
<span class="t-selected">▸</span><span class="t-accent"> 1  INVITE     alice          bob            192.0.2.1      192.0.2.2      </span><span class="t-good">InCall</span><span class="t-accent">         12  +0.000s     847ms</span>
  <span class="t-accent">2  INVITE     charlie        dave           192.0.2.3      192.0.2.4      </span><span class="t-warn">Ringing</span><span class="t-accent">         6  +1.234s     --</span>
  <span class="t-accent">3  REGISTER   admin          --             192.0.2.5      192.0.2.1      </span><span class="t-good">Registered</span><span class="t-accent">      4  +0.012s     --</span>
  <span class="t-accent">4  INVITE     +15551234      +15559876      192.0.2.6      192.0.2.7      </span><span class="t-bad">Failed</span><span class="t-accent">          8  +3.456s     --</span>
  <span class="t-accent">5  INVITE     1005           1006           192.0.2.1      192.0.2.2      </span><span class="t-good">Completed</span><span class="t-accent">      14  +0.003s     923ms</span>
  <span class="t-accent">6  OPTIONS    monitor        --             192.0.2.8      192.0.2.1      </span><span class="t-good">Completed</span><span class="t-accent">       2  +0.001s     --</span>
  <span class="t-accent">7  INVITE     1010           +441234567     192.0.2.9      192.0.2.7      </span><span class="t-good">InCall</span><span class="t-accent">         10  +0.215s     1.2s</span>
<span class="t-muted">  Esc Quit  Enter Show  F2 Save  F7 Filter  F8 Settings  F10 Columns  Tab Streams</span></pre>
</div>

> **Tip:** Press `Space` to star dialogs — a starred row shows `[*]` in the `#` column (the `▸` above is just the cursor). `F2` then saves only the starred dialogs, and `Enter` opens two or more of them as a single merged flow. Use `<` / `>` to sort by different columns and `Z` to reverse sort direction.

### Call flow view

The call flow shows a ladder diagram for a selected dialog, with timing, SDP, and RTP quality indicators.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Call Flow</span>
</div>
<pre class="terminal-body"><span class="t-header">    192.0.2.1:5060           192.0.2.3:5060           192.0.2.2:5060</span>
<span class="t-header">     (alice UAC)           (OpenSIPS proxy)             (bob UAS)</span>
<span class="t-muted">          |                        |                        |</span>
<span class="t-accent"> +0.000s  </span><span class="t-good">|------- INVITE --------&gt;|</span><span class="t-muted">                        |</span>
<span class="t-accent"> +0.003s  </span><span class="t-warn">|&lt;--------- 100 ---------|</span><span class="t-muted">                        |</span>
<span class="t-accent"> +0.005s  </span><span class="t-muted">|                        </span><span class="t-good">|------- INVITE --------&gt;|</span>
<span class="t-accent"> +0.008s  </span><span class="t-muted">|                        </span><span class="t-warn">|&lt;--------- 100 ---------|</span>
<span class="t-accent"> +0.847s  </span><span class="t-muted">|                        </span><span class="t-warn">|&lt;--------- 180 ---------|</span>  <span class="t-badge-delta">+839ms</span>
<span class="t-accent"> +0.850s  </span><span class="t-warn">|&lt;--------- 180 ---------|</span><span class="t-muted">                        |</span>
<span class="t-accent"> +2.134s  </span><span class="t-muted">|                        </span><span class="t-good">|&lt;--------- 200 ---------|</span>  <span class="t-badge-delta">+1.28s</span>
<span class="t-accent"> +2.137s  </span><span class="t-good">|&lt;--------- 200 ---------|</span><span class="t-muted">                        |</span>
<span class="t-accent"> +2.140s  </span><span class="t-good">|--------- ACK ---------&gt;|</span><span class="t-muted">                        |</span>
<span class="t-accent"> +2.143s  </span><span class="t-muted">|                        </span><span class="t-good">|--------- ACK ---------&gt;|</span>
<span class="t-muted">          |</span><span class="t-good"> ██ RTP PCMU MOS 4.2 ██ </span><span class="t-muted">|                        |</span>
<span class="t-muted">          |                        |</span><span class="t-good"> ██ RTP PCMU MOS 4.1 ██ </span><span class="t-muted">|</span>
<span class="t-accent">+65.320s  </span><span class="t-muted">|                        </span><span class="t-bad">|&lt;--------- BYE ---------|</span>
<span class="t-accent">+65.323s  </span><span class="t-bad">|&lt;--------- BYE ---------|</span><span class="t-muted">                        |</span>
<span class="t-accent">+65.326s  </span><span class="t-good">|------- 200 OK --------&gt;|</span><span class="t-muted">                        |</span>
<span class="t-muted">          |                        |                        |</span>
<span class="t-muted">  Esc Back  Enter Raw  Space Diff  d SDP  t Time  m Mark  x Extended  F6 RTP</span></pre>
</div>

> **Tip:** Press `m` to set a mark at any message, then navigate to another message to see the delta badge showing elapsed time between them. Press `M` to clear the mark. Use `d` to cycle through SDP display modes (none / summary / full).

### Raw message view

Full SIP message with optional syntax highlighting, searchable.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Raw Message</span>
</div>
<pre class="terminal-body"><span class="t-good">INVITE</span> sip:bob@192.0.2.2:5060 SIP/2.0
<span class="t-header">Via:</span> SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-524287-1
<span class="t-header">Max-Forwards:</span> 70
<span class="t-header">From:</span> "alice" &lt;sip:alice@192.0.2.1&gt;;tag=as6e4f2c8b
<span class="t-header">To:</span> &lt;sip:bob@192.0.2.2&gt;
<span class="t-header">Contact:</span> &lt;sip:alice@192.0.2.1:5060&gt;
<span class="t-header">Call-ID:</span> 3c9a82f1e7b4@192.0.2.1
<span class="t-header">CSeq:</span> 102 INVITE
<span class="t-header">User-Agent:</span> Olle/1.0
<span class="t-header">Content-Type:</span> application/sdp
<span class="t-header">Content-Length:</span> 263

<span class="t-accent">v=</span>0
<span class="t-accent">o=</span>alice 2890844526 2890844526 IN IP4 192.0.2.1
<span class="t-accent">s=</span>-
<span class="t-accent">c=</span>IN IP4 192.0.2.1
<span class="t-accent">t=</span>0 0
<span class="t-accent">m=</span>audio 10000 RTP/AVP 0 8 101
<span class="t-accent">a=</span>rtpmap:0 PCMU/8000
<span class="t-accent">a=</span>rtpmap:8 PCMA/8000
<span class="t-accent">a=</span>rtpmap:101 telephone-event/8000
<span class="t-accent">a=</span>fmtp:101 0-16
<span class="t-muted">  Esc Back  / Search  s Highlight  c Color</span></pre>
</div>

### RTP streams view

Shows all tracked RTP streams with quality metrics. Switch here from the Call List with `Tab`.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- RTP Streams</span>
</div>
<pre class="terminal-body"><span class="t-header"> RTP Streams: 14 tracked                                                         </span>
<span class="t-muted">  #  SSRC        Src IP:Port          Dst IP:Port          Codec   Pkts    Jitter  Loss%   MOS</span>
<span class="t-selected">▸</span><span class="t-accent"> 1  0x1a2b3c4d  192.0.2.1:10000      192.0.2.2:20000      PCMU    4820    </span><span class="t-good">2.1ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.2</span>
  <span class="t-accent">2  0x5e6f7a8b  192.0.2.2:20000      192.0.2.1:10000      PCMU    4815    </span><span class="t-good">1.8ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.3</span>
  <span class="t-accent">3  0x9c0d1e2f  192.0.2.6:12000      192.0.2.7:22000      PCMA    1205    </span><span class="t-warn">18.3ms</span><span class="t-accent">  </span><span class="t-warn">1.2%</span><span class="t-accent">    </span><span class="t-warn">3.4</span>
  <span class="t-accent">4  0xa1b2c3d4  192.0.2.7:22000      192.0.2.6:12000      PCMA    1198    </span><span class="t-bad">45.7ms</span><span class="t-accent">  </span><span class="t-bad">3.8%</span><span class="t-accent">    </span><span class="t-bad">2.1</span>
  <span class="t-accent">5  0xe5f60718  192.0.2.9:14000      192.0.2.7:24000      opus    9612    </span><span class="t-good">3.2ms</span><span class="t-accent">   </span><span class="t-good">0.1%</span><span class="t-accent">    </span><span class="t-good">4.1</span>
  <span class="t-accent">6  0x29304150  192.0.2.7:24000      192.0.2.9:14000      opus    9608    </span><span class="t-good">2.9ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.2</span>
  <span class="t-muted">7  0xdeadbeef  192.0.2.3:16000      --                   PCMU    340     </span><span class="t-bad">--</span><span class="t-muted">      </span><span class="t-bad">--</span><span class="t-muted">      </span><span class="t-bad">orphan</span>
<span class="t-muted">  Tab Call List  Esc Back  F7 Filter</span></pre>
</div>

> **Tip:** Streams marked `orphan` have no matching SIP dialog. This often indicates RTP arriving on unexpected ports (check your NAT/ALG config) or calls that started before capture began.

### Filter dialog (F7)

The filter popup lets you build filter expressions with text fields and checkboxes for common options.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Filter Dialog</span>
</div>
<pre class="terminal-body"><span class="t-muted"> ┌──────────────────── Filter ────────────────────┐</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-header">From:</span>     <span class="t-selected">[alice                       ]</span>      <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-header">To:</span>       [                            ]      <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-header">Filter:</span>   [method == 'INVITE'          ]      <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-good">[x]</span> Case insensitive                          <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-muted">[ ]</span> Invert match                              <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-muted">[ ]</span> Calls only                                <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> │</span>     <span class="t-good">[ Apply ]</span>          <span class="t-muted">[ Cancel ]</span>              <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> └────────────────────────────────────────────────┘</span>
<span class="t-muted"> Tab: next field  Enter: apply  Esc: cancel  F9: clear all</span></pre>
</div>

> **Tip:** The Filter field accepts the full [Filter DSL](filter-dsl.md) syntax. Combine it with the From/To text fields for powerful multi-criteria matching. Press `F9` to clear all filters at once.

### Save dialog (F2)

Save captured data in multiple formats. Use `Tab` to cycle through formats.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Save Capture</span>
</div>
<pre class="terminal-body"> <span class="t-muted">┌────────────────── Save Capture ──────────────────┐</span>
 <span class="t-muted">│</span>                                                  <span class="t-muted">│</span>
 <span class="t-muted">│</span>  <span class="t-header">Format:</span>  <span class="t-good">PCAP</span> <span class="t-muted">│ PCAP-NG │ TXT │ Mermaid</span>         <span class="t-muted">│</span>
 <span class="t-muted">│</span>                                                  <span class="t-muted">│</span>
 <span class="t-muted">│</span>  <span class="t-header">File:</span>    <span class="t-selected">[/tmp/capture.pcap           ]</span>         <span class="t-muted">│</span>
 <span class="t-muted">│</span>                                                  <span class="t-muted">│</span>
 <span class="t-muted">│</span>  <span class="t-muted">Saving: All 47 dialogs</span>                          <span class="t-muted">│</span>
 <span class="t-muted">│</span>  <span class="t-accent">(3 selected -- will save selected only)</span>         <span class="t-muted">│</span>
 <span class="t-muted">│</span>                                                  <span class="t-muted">│</span>
 <span class="t-muted">│</span>     <span class="t-good">[ Save ]</span>           <span class="t-muted">[ Cancel ]</span>                <span class="t-muted">│</span>
 <span class="t-muted">│</span>                                                  <span class="t-muted">│</span>
 <span class="t-muted">└──────────────────────────────────────────────────┘</span>
 <span class="t-muted">Tab: cycle format  Enter: save  Esc: cancel</span></pre>
</div>

> **Tip:** Select specific dialogs in the Call List with `Space` before pressing `F2`. The save dialog shows the count and saves only those. **Mermaid** format exports a sequence diagram you can paste into documentation.

### Settings dialog (F8)

Toggle display options without leaving the TUI.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Settings</span>
</div>
<pre class="terminal-body"> <span class="t-muted">┌─────────────────── Settings ───────────────────┐</span>
 <span class="t-muted">│</span>                                                <span class="t-muted">│</span>
 <span class="t-muted">│</span>  <span class="t-selected">▸ Color mode         </span><span class="t-good">always</span>                   <span class="t-muted">│</span>
 <span class="t-muted">│</span>    Timestamp mode     <span class="t-accent">delta-prev</span>               <span class="t-muted">│</span>
 <span class="t-muted">│</span>    Autoscroll         <span class="t-good">on</span>                       <span class="t-muted">│</span>
 <span class="t-muted">│</span>    Raw preview        <span class="t-bad">off</span>                      <span class="t-muted">│</span>
 <span class="t-muted">│</span>    SDP display        <span class="t-accent">summary</span>                  <span class="t-muted">│</span>
 <span class="t-muted">│</span>    Syntax highlighting <span class="t-good">on</span>                      <span class="t-muted">│</span>
 <span class="t-muted">│</span>                                                <span class="t-muted">│</span>
 <span class="t-muted">└────────────────────────────────────────────────┘</span>
 <span class="t-muted">Up/Down: navigate  Enter/Space: toggle  Esc: close</span></pre>
</div>

## See also

- [theme-guide.md](theme-guide.md) — recolor every TUI element via `[theme]`
- [config-reference.md](config-reference.md) — rebind the 11 configurable keys
  via `[keybindings]`
- [filter-dsl.md](filter-dsl.md) — the expression language the F7 filter
  dialog compiles down to (and the `--filter` flag exposes directly)
