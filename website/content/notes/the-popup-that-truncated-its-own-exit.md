+++
title = "TUI popups: a cut-off Esc hint and crashes on small terminals, fixed in 0.5.142"
date = 2026-09-01
updated = 2026-10-11
description = "Why the Name Address popup hid its Esc key, why the Filter popup could close the whole TUI on a small terminal, and what sipnab 0.5.142 changed so every popup shows its closing key and survives any terminal size."

[extra]
kind = "postmortem"
+++

## In short

sipnab's terminal interface opens small windows (popups) for tasks. Examples
are naming an address or setting a filter.

- Up to version 0.5.141, the popup for naming an address cut off the end of
  its help line.
  - That end was the text `Esc cancel`, which says how to close it.
- Three other popups did not mention the Esc key at all.
- The Filter popup could crash the interface when the terminal window was
  small.

Version 0.5.142:

- sizes each popup to its text,
- shows the Esc key in every popup,
- draws text so that a small window can no longer crash the interface.

## What happened

In the call list, pressing `N` opens the **Name Address** popup. It gives a
host name to an IP address (see
[Name resolution](@/docs/keybindings.md#name-resolution)).

When the selected call has two addresses, the popup's last line is:

```text
  Tab switch endpoint · Enter save all · empty clears · Esc cancel
```

- That line is 66 characters wide.
- The popup was at most 60 characters wide.
- So the end of the line, `Esc cancel`, was not shown.
- When the selected call has one address, the line is shorter
  (`  Enter save · empty name clears · Esc cancel`, 45 characters).
  - That line fit.
  - So the problem appeared only for calls with two addresses.

The tests written for this found three more problems. The fix commit,
506851b5, records them:

- The **Filter** popup (F7), the **Settings** popup (F8) and the **Column
  selector** (F10) all close on Esc.
  - None of them said so inside the popup.
- The Filter popup crashed the interface at 66 columns by 12 rows.
- The Settings popup crashed when the tests drew it into an area fewer than
  six rows high.
  - In the running program, a terminal smaller than 40 columns by 6 rows
    shows the notice `Terminal too small` instead of any popup.
  - That notice existed before this fix.
  - So the 66 by 12 case is the one a user could reach.

A crash closes the whole interface, including a live capture in progress.

## Why it happened

- **Fixed width.**
  - The Name Address popup used a fixed width of 60 characters. It did not use
    the width of its own text.
  - The text component it draws with does not wrap long lines onto a second
    row.
  - It cuts them off and reports no error.
  - So nothing signaled the loss.
- **No rule that a popup names its exit.**
  - No test checked that a popup shows the key that closes it.
- **Fixed height.**
  - The Filter and Settings popups placed their rows using a fixed height.
  - On a terminal shorter than that height, the popups asked the drawing
    library's text function (`Buffer::set_string`) to write outside the
    screen.
  - That function stops the program when its position lies outside the
    screen.

## What changed

All of this shipped in 0.5.142 (2026-09-01).

- **Popups take the width of their text.**
  - The Name Address popup measures its longest line and adds three columns:
    - one for each border,
    - one so the text does not touch the right border.
  - It still shrinks to fit a narrow terminal.
  - The same popup on a 100-column terminal now looks like this. It was
    captured from a run on `tests/pcap-samples/sip-rtp-g711.pcap`:

  ```text
                 ┌ Name Address ─────────────────────────────────────────────────────┐
                 │  Endpoint:  10.0.2.20   10.0.2.15                                 │
                 │  IP:   10.0.2.20                                                  │
                 │  Name:                                                            │
                 │                                                                   │
                 │  Tab switch endpoint · Enter save all · empty clears · Esc cancel │
                 └───────────────────────────────────────────────────────────────────┘
  ```

- **Every popup names its exit.**
  - The Filter popup now shows `Tab move · Enter apply · Esc cancel`.
  - The Settings popup shows `↑/↓ move · Enter toggle · Esc close`.
  - The Column selector shows `Space: toggle  Enter: apply  Esc: close`.
- **Text that does not fit no longer crashes the interface.**
  - Every place in the interface that called `Buffer::set_string` now calls
    one function, `set_string_clipped`, instead.
  - It skips a write that falls outside the screen.
  - It shortens a line at the right edge.
- **Tests hold each of these in place** (all in `src/tui/render/popups.rs`):
  - `no_popup_shows_more_text_when_the_terminal_grows` draws every popup at
    100x40 and again at 240x60.
    - It requires the same text in both.
    - If the larger terminal shows more, the smaller one was cutting text
      off.
    - This test does not need to know what any popup says.
  - `every_overlay_names_the_key_that_closes_it` requires `Esc` in every
    popup.
  - `every_overlay_survives_an_exhaustive_size_sweep` draws every popup at
    every width from 1 to 90 columns.
    - It uses heights of 1, 2, 3, 5, 8, 12, 20 and 30 rows.
    - It fails on any crash.
  - `every_overlay_survives_a_tiny_terminal` does the same for six named
    sizes, including 4x3 and 66x12.
  - `no_tui_code_writes_through_the_unguarded_set_string` fails if code calls
    `Buffer::set_string` directly. It checks code in `render/popups.rs`,
    `call_list.rs` and `call_flow/render.rs`.

A further test is `every_tui_overlay_is_covered_by_these_gates`.

- It finds the list of popups by counting places that clear a screen area
  before drawing a popup.
  - It counts in `src/tui/render/popups.rs` and `src/tui/call_list.rs`.
- It fails if that count differs from the list of popups the other tests use.
- So a popup added in one of those two files without a test fails the build.
- The count does not include a popup added in another file.
- Today no other file under `src/tui/` draws one.

## What you can check yourself

Open the interface on a capture in the repository. Select a call, and press
`N`. The last line of the popup ends in `Esc cancel`:

```bash
sipnab -I tests/pcap-samples/sip-rtp-g711.pcap
```

Make the terminal window small (for example 66 columns by 12 rows). Press F7
or F8. On 0.5.142 and later:

- sipnab draws as much of the popup as fits,
- the interface keeps running.

## Terms used here

- **TUI**: terminal user interface, sipnab's full-screen interactive view.
- **Popup**: a small window drawn on top of the main view for one task.
- **Endpoint**: one IP address taking part in a call.
- **Crash**: the program stops unexpectedly. Here it closes the whole TUI.
- **Test**: an automated check that runs on every build and fails when the
  behavior it describes stops working.

## Related guides

- [Name resolution and the `N` popup](@/docs/keybindings.md#name-resolution)
- [Filter popup keys](@/docs/keybindings.md#filter-popup)
- [Settings popup keys](@/docs/keybindings.md#settings-popup)
- [Column selector keys](@/docs/keybindings.md#column-selector)
