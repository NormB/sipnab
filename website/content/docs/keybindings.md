+++
title = "Keybindings"
weight = 4
description = "Complete TUI keyboard shortcut reference for all views."
+++

> **Quick start:** `j`/`k` for vim-style up/down, `Enter` to drill into a call, `Esc` to go back, `Tab` to switch between Call List and RTP Streams.

Complete keyboard shortcut reference for sipnab's interactive TUI.

Keys marked with **(configurable)** can be remapped via the `[keybindings]` config section. See [Config Reference](@/docs/config.md) for details. All other keys are hardcoded.

## TUI Views

### Call List View

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
<span class="t-selected">▸</span><span class="t-accent"> 1  INVITE     alice          bob            10.0.0.1       10.0.0.2       </span><span class="t-good">InCall</span><span class="t-accent">         12  +0.000s     847ms</span>
  <span class="t-accent">2  INVITE     charlie        dave           10.0.0.3       10.0.0.4       </span><span class="t-warn">Ringing</span><span class="t-accent">         6  +1.234s     --</span>
  <span class="t-accent">3  REGISTER   admin          --             10.0.0.5       10.0.0.1       </span><span class="t-good">Registered</span><span class="t-accent">      4  +0.012s     --</span>
  <span class="t-accent">4  INVITE     +15551234      +15559876      10.0.0.6       10.0.0.7       </span><span class="t-bad">Failed</span><span class="t-accent">          8  +3.456s     --</span>
  <span class="t-accent">5  INVITE     1005           1006           10.0.0.1       10.0.0.2       </span><span class="t-good">Completed</span><span class="t-accent">      14  +0.003s     923ms</span>
  <span class="t-accent">6  OPTIONS    monitor        --             10.0.0.8       10.0.0.1       </span><span class="t-good">Completed</span><span class="t-accent">       2  +0.001s     --</span>
  <span class="t-accent">7  INVITE     1010           +441234567     10.0.0.9       10.0.0.7       </span><span class="t-good">InCall</span><span class="t-accent">         10  +0.215s     1.2s</span>
<span class="t-muted">  Esc Quit  Enter Show  F2 Save  F7 Filter  F8 Settings  F10 Columns  Tab Streams</span></pre>
</div>

> **Tip:** Press `Space` to multi-select dialogs (shown with `▸`). Press `F2` to save only the selected dialogs. Use `<` / `>` to sort by different columns and `Z` to reverse sort direction.

### Call Flow View

The call flow shows a ladder diagram for a selected dialog, with timing, SDP, and RTP quality indicators.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Call Flow</span>
</div>
<pre class="terminal-body"><span class="t-header">      10.0.0.1:5060          10.0.0.40:5060         10.0.0.2:5060</span>
<span class="t-header">      (alice UAC)             (OpenSIPS proxy)       (bob UAS)</span>
<span class="t-muted">          │                        │                        │</span>
<span class="t-accent"> +0.000s</span>  <span class="t-good">│------- INVITE -------->│</span>                        <span class="t-muted">│</span>
<span class="t-accent"> +0.003s</span>  <span class="t-warn">│<-------- 100 ----------│</span>                        <span class="t-muted">│</span>
<span class="t-accent"> +0.005s</span>  <span class="t-muted">│</span>                        <span class="t-good">│------- INVITE -------->│</span>
<span class="t-accent"> +0.008s</span>  <span class="t-muted">│</span>                        <span class="t-warn">│<------- 100 ---------│</span>
<span class="t-accent"> +0.847s</span>  <span class="t-muted">│</span>                        <span class="t-warn">│<------- 180 ---------│</span>  <span class="t-badge-delta">+839ms</span>
<span class="t-accent"> +0.850s</span>  <span class="t-warn">│<------- 180 ---------│</span>                        <span class="t-muted">│</span>
<span class="t-accent"> +2.134s</span>  <span class="t-muted">│</span>                        <span class="t-good">│<------- 200 ---------│</span>  <span class="t-badge-delta">+1.28s</span>
<span class="t-accent"> +2.137s</span>  <span class="t-good">│<------- 200 ---------│</span>                        <span class="t-muted">│</span>
<span class="t-accent"> +2.140s</span>  <span class="t-good">│--------- ACK --------->│</span>                        <span class="t-muted">│</span>
<span class="t-accent"> +2.143s</span>  <span class="t-muted">│</span>                        <span class="t-good">│--------- ACK --------->│</span>
<span class="t-muted">          │</span>    <span class="t-good">██████████ RTP (PCMU, MOS 4.2)</span>          <span class="t-muted">│</span>
<span class="t-muted">          │</span>    <span class="t-good">██████████ RTP (PCMU, MOS 4.1)</span>          <span class="t-muted">│</span>
<span class="t-accent">+65.320s</span>  <span class="t-muted">│</span>                        <span class="t-bad">│<------- BYE ---------│</span>
<span class="t-accent">+65.323s</span>  <span class="t-bad">│<------- BYE ---------│</span>                        <span class="t-muted">│</span>
<span class="t-accent">+65.326s</span>  <span class="t-good">│-------- 200 OK ------->│</span>                        <span class="t-muted">│</span>
<span class="t-muted">          │                        │                        │</span>
<span class="t-muted">  Esc Back  Enter Raw  Space Diff  d SDP  t Time  m Mark  x Extended  F6 RTP</span></pre>
</div>

> **Tip:** Press `m` to set a mark at any message, then navigate to another message to see the delta badge showing elapsed time between them. Press `M` to clear the mark. Use `d` to cycle through SDP display modes (none / summary / full).

### Raw Message View

Full SIP message with optional syntax highlighting, searchable.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Raw Message</span>
</div>
<pre class="terminal-body"><span class="t-good">INVITE</span> sip:bob@10.0.0.2:5060 SIP/2.0
<span class="t-header">Via:</span> SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-524287-1
<span class="t-header">Max-Forwards:</span> 70
<span class="t-header">From:</span> "alice" &lt;sip:alice@10.0.0.1&gt;;tag=as6e4f2c8b
<span class="t-header">To:</span> &lt;sip:bob@10.0.0.2&gt;
<span class="t-header">Contact:</span> &lt;sip:alice@10.0.0.1:5060&gt;
<span class="t-header">Call-ID:</span> 3c9a82f1e7b4@10.0.0.1
<span class="t-header">CSeq:</span> 102 INVITE
<span class="t-header">User-Agent:</span> Olle/1.0
<span class="t-header">Content-Type:</span> application/sdp
<span class="t-header">Content-Length:</span> 263

<span class="t-accent">v=</span>0
<span class="t-accent">o=</span>alice 2890844526 2890844526 IN IP4 10.0.0.1
<span class="t-accent">s=</span>-
<span class="t-accent">c=</span>IN IP4 10.0.0.1
<span class="t-accent">t=</span>0 0
<span class="t-accent">m=</span>audio 10000 RTP/AVP 0 8 101
<span class="t-accent">a=</span>rtpmap:0 PCMU/8000
<span class="t-accent">a=</span>rtpmap:8 PCMA/8000
<span class="t-accent">a=</span>rtpmap:101 telephone-event/8000
<span class="t-accent">a=</span>fmtp:101 0-16
<span class="t-muted">  Esc Back  / Search  s Highlight  c Color</span></pre>
</div>

### RTP Streams View

Shows all tracked RTP streams with quality metrics. Switch here from the Call List with `Tab`.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- RTP Streams</span>
</div>
<pre class="terminal-body"><span class="t-header"> RTP Streams: 14 tracked                                                         </span>
<span class="t-muted">  #  SSRC        Src IP:Port          Dst IP:Port          Codec   Pkts    Jitter  Loss%   MOS</span>
<span class="t-selected">▸</span><span class="t-accent"> 1  0x1a2b3c4d  10.0.0.1:10000       10.0.0.2:20000       PCMU    4820    </span><span class="t-good">2.1ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.2</span>
  <span class="t-accent">2  0x5e6f7a8b  10.0.0.2:20000       10.0.0.1:10000       PCMU    4815    </span><span class="t-good">1.8ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.3</span>
  <span class="t-accent">3  0x9c0d1e2f  10.0.0.6:12000       10.0.0.7:22000       PCMA    1205    </span><span class="t-warn">18.3ms</span><span class="t-accent">  </span><span class="t-warn">1.2%</span><span class="t-accent">    </span><span class="t-warn">3.4</span>
  <span class="t-accent">4  0xa1b2c3d4  10.0.0.7:22000       10.0.0.6:12000       PCMA    1198    </span><span class="t-bad">45.7ms</span><span class="t-accent">  </span><span class="t-bad">3.8%</span><span class="t-accent">    </span><span class="t-bad">2.1</span>
  <span class="t-accent">5  0xe5f60718  10.0.0.9:14000       10.0.0.7:24000       opus    9612    </span><span class="t-good">3.2ms</span><span class="t-accent">   </span><span class="t-good">0.1%</span><span class="t-accent">    </span><span class="t-good">4.1</span>
  <span class="t-accent">6  0x29304150  10.0.0.7:24000       10.0.0.9:14000       opus    9608    </span><span class="t-good">2.9ms</span><span class="t-accent">   </span><span class="t-good">0.0%</span><span class="t-accent">    </span><span class="t-good">4.2</span>
  <span class="t-muted">7  0xdeadbeef  10.0.0.3:16000       --                   PCMU    340     </span><span class="t-bad">--</span><span class="t-muted">      </span><span class="t-bad">--</span><span class="t-muted">      </span><span class="t-bad">orphan</span>
<span class="t-muted">  Tab Call List  Esc Back  F7 Filter</span></pre>
</div>

> **Tip:** Streams marked `orphan` have no matching SIP dialog. This often indicates RTP arriving on unexpected ports (check your NAT/ALG config) or calls that started before capture began.

### Filter Dialog (F7)

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

> **Tip:** The Filter field accepts the full [Filter DSL](@/docs/filter-dsl.md) syntax. Combine it with the From/To text fields for powerful multi-criteria matching. Press `F9` to clear all filters at once.

### Save Dialog (F2)

Save captured data in multiple formats. Use `Tab` to cycle through formats.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Save Capture</span>
</div>
<pre class="terminal-body"><span class="t-muted"> ┌─────────────────── Save Capture ──────────────────┐</span>
<span class="t-muted"> │</span>                                                  <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-header">Format:</span>  <span class="t-good">PCAP</span> <span class="t-muted">│ PCAP-NG │ TXT │ Mermaid</span>     <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                  <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-header">File:</span>    <span class="t-selected">[/tmp/capture.pcap           ]</span>         <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                  <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-muted">Saving: All 47 dialogs</span>                          <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-accent">(3 selected -- will save selected only)</span>         <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                  <span class="t-muted">│</span>
<span class="t-muted"> │</span>     <span class="t-good">[ Save ]</span>           <span class="t-muted">[ Cancel ]</span>                <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                  <span class="t-muted">│</span>
<span class="t-muted"> └──────────────────────────────────────────────────┘</span>
<span class="t-muted"> Tab: cycle format  Enter: save  Esc: cancel</span></pre>
</div>

> **Tip:** Select specific dialogs in the Call List with `Space` before pressing `F2`. The save dialog will show how many are selected and save only those. **Mermaid** format exports a sequence diagram you can paste into documentation.

### Settings Dialog (F8)

Toggle display options without leaving the TUI.

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">sipnab -- Settings</span>
</div>
<pre class="terminal-body"><span class="t-muted"> ┌──────────────────── Settings ───────────────────┐</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> │</span>  <span class="t-selected">▸ Color mode         </span><span class="t-good">always</span>                   <span class="t-muted">│</span>
<span class="t-muted"> │</span>    Timestamp mode     <span class="t-accent">delta-prev</span>               <span class="t-muted">│</span>
<span class="t-muted"> │</span>    Autoscroll         <span class="t-good">on</span>                       <span class="t-muted">│</span>
<span class="t-muted"> │</span>    Raw preview         <span class="t-bad">off</span>                     <span class="t-muted">│</span>
<span class="t-muted"> │</span>    SDP display         <span class="t-accent">summary</span>                 <span class="t-muted">│</span>
<span class="t-muted"> │</span>    Syntax highlighting <span class="t-good">on</span>                      <span class="t-muted">│</span>
<span class="t-muted"> │</span>                                                <span class="t-muted">│</span>
<span class="t-muted"> └────────────────────────────────────────────────┘</span>
<span class="t-muted"> Up/Down: navigate  Enter/Space: toggle  Esc: close</span></pre>
</div>

---

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
| F10 | Column selector **(configurable: `column_selector`)**. Opens a popup to show/hide columns in the Call List (e.g., PDD, Source IP, Destination). |

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
| \[ | Scroll detail panel up |
| \] | Scroll detail panel down |
| e | Toggle fold/expand for selected message |
| m | Set mark at current message. Places a reference marker on the current message. Navigate to another message to see the **delta** time between the mark and your current position -- useful for measuring delays between specific SIP messages. |
| M | Clear mark |
| E | Export Mermaid sequence diagram to clipboard |
| x / F4 | Toggle extended multi-leg flow **(configurable: `extended_flow`)**. Shows related B2BUA/SBC call legs together in the flow view -- useful for tracing calls through proxies and back-to-back user agents. |
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
