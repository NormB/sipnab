# TUI Walkthrough

Your first analysis in the interactive TUI, step by step — open a capture, read
the ladder, measure a delay, and inspect RTP.

> New to sipnab? Start here. This is a guided first run through the interactive
> TUI. Every key you press is called out, and the full reference lives in
> [Keybindings](keybindings.md). If you prefer the command line, see the
> [Cookbook](examples.md) instead.

## 1. Open a capture

Point sipnab at a pcap and it drops you straight into the **Call List**:

```bash
sipnab -I capture.pcap
```

No file handy? Launch it live on an interface (needs `sudo`), or start with no
argument and open a file from inside the TUI with `O` (the File Open dialog):

```bash
sudo sipnab -d eth0     # live capture
sipnab                  # then press O to open a pcap
```

You can open a different capture at any time with `O` -- no restart needed.

## 2. Find your way around the Call List

The Call List is the home view: one row per SIP dialog, with method, endpoints,
state, message count, and PDD (post-dial delay).

- `j` / `k` (or `Down` / `Up`) move the selection; `PgUp` / `PgDn`, `Home`, `End` jump around.
- `<` / `>` sort by the previous / next column; `Z` reverses the direction. Sort by **State** to bring `Failed` calls to the top, or by **PDD** to find slow setups.
- `t` cycles the timestamp mode (absolute → delta-prev → delta-first → scaled). Delta-prev is the one that makes latency spikes jump out.
- Too many columns, or missing one you want (Source IP, PDD)? `F10` opens the column selector.

Land on the call you care about, then press `Enter`.

## 3. Read the call-flow ladder

`Enter` opens the **Call Flow** -- a ladder diagram of the dialog across every
host it touched (UAC → proxy → UAS), with a detail panel beside it.

- `j` / `k` walk message-to-message; the detail panel updates to show the parsed message under the cursor.
- `d` cycles how SDP is shown in the detail panel (none / summary / full).
- `w` toggles line wrapping in the detail panel; with wrap off, long lines truncate and a horizontal scrollbar appears (`Left` / `Right` scroll it).
- `Enter` on a message opens the full-screen **Raw Message** view (`/` searches within it, `n` / `N` jump between matches, `Esc` returns).
- `c` recolors the ladder by method, Call-ID, or CSeq; `t` shares the timestamp mode with the Call List.

`Esc` takes you back to the Call List at any time.

## 4. Measure the delay between two messages

This is the trick most people come to sipnab for. In the Call Flow:

1. Move to the first message (say the `INVITE`) and press `m` to drop a **mark**.
2. Navigate to a later message (the `200 OK`). A **delta badge** appears showing the elapsed time between the mark and your current position.
3. Press `M` to clear the mark.

Now you can read "how long from INVITE to 200 OK?" straight off the ladder,
without doing timestamp math in your head.

## 5. Compare two messages side by side

Suspect a header changed across a retransmit or a proxy hop? Press `Space` on
one message, then `Space` on another, to open the **Message Diff** -- a
line-by-line comparison. `Esc` returns to the ladder.

## 6. Search and filter

- `/` searches the current view (Call List, Raw Message, or RTP Streams).
- `F7` opens the **Filter dialog**, which accepts the full [Filter DSL](filter-dsl.md) plus quick From/To fields and checkboxes. Try `state == 'Failed'` to keep only calls that never established, or `rtp.mos < 3.0` for poor audio.
- `F9` clears the active filter; `i` prunes the dialogs that do *not* match, keeping only the matches, and `I` prunes the ones that do.

## 7. Inspect RTP quality

Press `Tab` to switch from the Call List to the **RTP Streams** view: every
media stream with codec, packet count, jitter, loss, and MOS. Streams flagged
`orphan` have no matching SIP dialog (often a NAT/ALG symptom).

Press `Enter` on a stream -- or on an `██ RTP ██` bar back in the Call Flow --
to open **Stream Detail**: MOS, jitter statistics, quality intervals, burst/gap
analysis, silence detection, and MOS/jitter sparklines. With an `audio` build,
`Shift+P` plays the stream (G.711). `Tab` switches back to the Call List.

## 8. Trace a call through proxies (multi-leg)

If a call crossed a B2BUA or SBC, press `x` (or `F4`) in the Call Flow to toggle
**extended multi-leg flow** -- the related legs render together in one ladder,
so you can follow the call end-to-end through the middle boxes.

## 9. Save what you found

Select the dialogs you want with `Space` in the Call List (they show a `▸`),
then press `F2`. In the Save dialog, `Tab` cycles the format -- PCAP, PCAP-NG,
TXT, JSON, NDJSON, CSV, **Mermaid** (a sequence diagram for your ticket/wiki),
Markdown, WAV, SIPp XML, RTP JSON -- and `Enter` writes the file. If nothing is
selected, it saves everything.

## Where to go next

- `F1` (or `?`) opens context help in any view -- the fastest way to see what a
  view can do without leaving it.
- [Keybindings](keybindings.md) -- the complete per-view reference, plus
  an annotated visual tour of every screen.
- [Theme Guide](theme-guide.md) -- recolor the TUI to taste.
- [Cookbook](examples.md) -- the same investigations as one-shot CLI
  commands, for scripting and CI.
