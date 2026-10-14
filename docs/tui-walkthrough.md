# Walk through the terminal UI

Your first analysis in the interactive TUI, step by step — open a capture, read
the ladder, measure a delay, and inspect RTP.

> New to sipnab? Start here. This is a guided first run through the interactive
> TUI.
>
> - It names every key you press.
> - The full reference lives in [Keybindings](keybindings.md).
> - If you prefer the command line, follow
>   [Triage a capture from the command line](first-cli-triage.md) instead.
> - The [Glossary](glossary.md) defines any term you do not recognize.

## Open a capture

No capture handy? Download the sample call the website uses:

```bash
curl -LO https://sipnab.com/demos/sample-call.pcap
```

Point sipnab at a pcap (packet capture) file. It drops you straight into the
**Call List**:

```bash
sipnab -I sample-call.pcap
```

To watch live traffic on an interface instead, run it with `sudo`. Opening a
capture device needs privilege:

```bash
sudo sipnab -d eth0
```

Or start with no argument at all. Then open a file from inside the TUI with
`O` (the File Open dialog):

```bash
sipnab
```

You can open a different capture at any time with `O`. You do not need to restart.

## Find your way around the call list

The Call List is the home view. It has one row per SIP
[dialog](glossary.md#dialog) (every message that shares a Call-ID). Each row
shows:

- method,
- endpoints,
- state,
- message count,
- [PDD](glossary.md#pdd) (post-dial delay, the wait between the INVITE and the
  first ringing response).

The three lines above it say what you are looking at:

- the source (`File: capture.pcap` or `Live capture: eth0`), with how many
  dialogs the list shows out of how many sipnab holds,
- then the capture (BPF) filter,
- then the view filter.

The bar at the bottom lists the keys of the view you are in. `F1` opens the
help from any view.

- `j` / `k` (or `Down` / `Up`) move the selection. `PgUp` / `PgDn`, `Home`, `End` jump around.
- `<` / `>` sort by the previous / next column. `Z` reverses the direction.
  - Sort by **State** to bring `Failed` calls to the top.
  - Sort by **PDD** to find slow setups.
- `t` cycles the timestamp mode (absolute → delta from previous → delta from first → scaled). Delta from previous is the one that makes latency spikes jump out.
- Too many columns, or missing one you want (Source IP, PDD)? `F10` opens the column selector.

Land on the call you care about, then press `Enter`.

## Read the call-flow ladder

`Enter` opens the **Call Flow**. It is a ladder diagram of the dialog across
every host it touched (UAC → proxy → UAS). A detail pane sits beside it.

- `j` / `k` walk message-to-message. The detail pane updates to show the parsed message under the cursor.
- `d` cycles how the detail pane shows SDP (hidden / summary / full).
- `w` toggles line wrapping in the detail pane.
  - With wrap off, long lines truncate and a horizontal scrollbar appears.
  - Press `Tab` to put the cursor in the detail pane. `Left` / `Right` then scroll it sideways.
  - Without that focus, the same two keys resize the detail pane instead.
  - `R` hides or shows it.
- `Enter` on a message opens the full-screen **Raw Message** view.
  - `/` searches within it.
  - `n` / `N` jump between matches.
  - `Esc` returns.
- `c` recolors the ladder by method, Call-ID, or CSeq. `t` shares the timestamp mode with the Call List.

`Esc` takes you back to the Call List at any time.

## Measure the delay between two messages

This is the trick most people come to sipnab for. In the Call Flow:

- Move to the first message (say the `INVITE`). Press `m` to drop a **mark**.
- Navigate to a later message (the `200 OK`). A **delta badge** appears. It shows the elapsed time between the mark and your current position.
- Press `M` to clear the mark.

Now you can read "how long from INVITE to 200 OK?" straight off the ladder.
You do not need to do timestamp math in your head.

## Compare two messages side by side

Suspect a header changed across a retransmit or a proxy hop?

- Press `Space` on one message.
- Then press `Space` on another. This opens the **Message Diff**, a
  line-by-line comparison.
- `Esc` returns to the ladder.

## Search and filter

- `/` searches the current view (Call List, Raw Message, or RTP Streams).
- `F7` opens the **Filter dialog**.
  - It offers From/To, source/destination, payload, time bounds and method fields.
  - These fields build a filter.
  - There is no free-form expression field.
  - Pass the full [Filter DSL](filter-dsl.md) through CLI `--filter`, for example `rtp.mos < 3.0`.
- `F9` clears the view filter and any kept search.
- `i` prunes the dialogs that do *not* match, keeping only the matches.
- `I` prunes the ones that do.

## Inspect RTP quality

Press `Tab` to switch from the Call List to the **RTP Streams** view. It lists
every media stream with:

- codec,
- packet count,
- [jitter](glossary.md#jitter) (how much packet spacing varies),
- loss.

Streams flagged `orphan` have no matching SIP dialog. That is often a sign that
NAT or a SIP-aware router rewrote the media address.

From a Call Flow, `r` opens the same view narrowed to that call's streams.

- `a` switches between that call's streams and every stream.
- `Esc` returns to the Call Flow.
- A stream is a call's when an SDP sipnab captured names the stream's address
  and port.
- A stream with NAT on both ends, or one sent over ICE or TURN, can stay
  unlinked. Status line 3 counts those, and `a` shows them.

Press `Enter` on a stream to open **Stream Detail**. You can also press it on
an `██ RTP ██` bar back in the Call Flow. Stream Detail shows:

- [MOS](glossary.md#mos) (mean opinion score, an estimate of how the call
  sounded),
- jitter statistics,
- quality intervals,
- burst/gap analysis,
- silence detection,
- MOS/jitter sparklines.

A stream whose far end sent RTCP XR gains a **Reported by Far End (RTCP XR)**
section at the bottom.

- It holds that endpoint's own R-factor, MOS-LQ, MOS-CQ, delays and discard
  rate.
- Everything above that section is what sipnab measured. Nothing in the
  section moves those numbers.

With an `audio` build, `Shift+P` plays the stream (G.711). `Esc` returns to the
RTP Streams list. `Tab` there switches back to the Call List.

## Trace a call through proxies (multi-leg)

A call may cross a [B2BUA](glossary.md#b2bua) or [SBC](glossary.md#sbc).

- That is a box that ends the call on one side and starts a new one on the
  other.
- So each side has its own Call-ID.

Then press `x` (or `F4`) in the Call Flow to toggle **extended multi-leg
flow**.

- The related legs render together in one ladder.
- So you can follow the call end-to-end through the middle boxes.

## Save what you found

Select the dialogs you want with `Space` in the Call List. Their checkbox
changes from `[ ]` to `[*]`. Then press `F2`.

In the Save dialog, `Tab` cycles the format:

- PCAP,
- PCAP-NG,
- TXT,
- JSON,
- NDJSON,
- CSV,
- **HTML** (a self-contained ladder diagram, drawn with Mermaid, for your
  ticket or wiki),
- Markdown,
- WAV,
- SIPp XML,
- RTP JSON.

`Enter` writes the file. `Shift+Tab` or `Up` / `Down` cycle the same list. With
nothing selected, it saves everything.

**The HTML diagram draws at most 200 messages.**

- A call with more exports its first 200 as arrows.
- A note inside the diagram names how many messages the call really had.
- The cap exists because the diagram renderer draws nothing at all past 500
  arrows and notes.
- Without the cap, a long call would export as a blank panel with no error.

## Send your notes with the frames they are about

Select the message that matters and press `C`. Type the note and press Enter.

- sipnab shows it in a pane under the flow titled "operator note — not sipnab
  analysis".
- It marks the row with `✎`.
- Press `C` again to amend it, or clear the text to remove it.

To hand the capture over, press `F2`, Tab to PCAP-NG and save.

- Each note is the packet comment on its message's frame. Wireshark shows it.
- The comment has a line naming the frame you typed it on.

To pick the session up later, Tab to NOTES instead. Then start sipnab again with
`--notes` and that file.

- The capture you send carries your notes.
- sipnab never reads them back as analysis.

## Where to go next

- `F1` (or `?`) opens context help in any view. It is the fastest way to see
  what a view can do without leaving it.
- [Keybindings](keybindings.md) -- the complete per-view reference, plus
  an annotated visual tour of every screen.
- [Theme Guide](theme-guide.md) -- recolor the TUI to taste.
- [Cookbook](examples.md) -- the same investigations as one-shot CLI
  commands, for scripting and CI.

<details>
<summary>Why / how we know</summary>

- The 200-message cap is `MAX_MESSAGES` (200) in
  [`src/mermaid.rs`](https://github.com/NormB/sipnab/blob/main/src/mermaid.rs).
- The renderer's limit is `RENDERER_MAX_EDGES` (500) in the same file.
- The vendored Mermaid build refuses a diagram past that many edges outright. It
  does not draw part of it.
- Every arrow and every note is one edge.
- These all draw through that one generator, so they share the cap:
  - the TUI's HTML export,
  - the MCP `render_ladder` tool,
  - the browser analyzer.

</details>
