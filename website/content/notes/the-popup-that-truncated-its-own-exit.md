+++
title = "A popup that cut off the only key that closes it"
date = 2026-09-01
description = "A 60-column constant against a 66-column hint dropped `Esc cancel` off the right edge, silently. Writing the general gate found three more dialogs with the same defect and two crashes, one of them at 66x12."

[extra]
kind = "postmortem"
+++

Somebody pressed `N` in sipnab's TUI, and the popup that opened had its hint
line cut off mid-word.

```text
  Tab switch endpoint · Enter save all · empty clears · Esc cancel
```

That line is 66 columns. The popup was a constant 60 wide. The part that fell
off the right edge was `Esc cancel` — the only exit the dialog names.

## Why nothing failed

`Paragraph` in this rendering path has no `wrap`, so an overlong line does not
flow onto a second row. It truncates. Nothing panics, nothing logs, nothing
returns an error. The popup renders, and it renders slightly shorter than it
should.

The other arm of the same branch is why it survived. A single-endpoint capture
gets a shorter hint:

```text
  Enter save · empty name clears · Esc cancel
```

That fits at 60. The common case looked right, and only a two-endpoint call
tripped it.

## Size to what it says, not to a bigger constant

The tempting fix is 80. It fails the same way one IPv6 address later, and the
popup can carry a long address, a long name and an inline validation error at
once — none of which anybody sized 60 for.

The popup now measures the lines it has already built:

```rust
let content = lines
    .iter()
    .map(ratatui::text::Line::width)
    .max()
    .unwrap_or(0);
let desired = u16::try_from(content.max(title.len()).saturating_add(3))
    .unwrap_or(u16::MAX);
let popup_width = desired.clamp(20, area.width.saturating_sub(4).max(20));
```

`+3` covers the two borders and one column so the longest line does not sit
flush against the frame. The title has to fit between the corners too.

## The gate that needs to know nothing about the strings

A test asserting `Esc cancel` appears is a fine regression guard and it catches
one popup. The general form asks a different question:

```rust
/// No popup shows MORE text when the terminal grows.
///
/// The general detector, and the one that needs no knowledge of any
/// popup's strings. If a popup is complete at 100 columns, widening the
/// terminal to 240 cannot reveal anything new; if widening does reveal
/// something, the popup was clipping its own content at 100 and a user on
/// an ordinary terminal was reading a truncated dialog.
#[test]
fn no_popup_shows_more_text_when_the_terminal_grows() {
```

Render every overlay at 100x40, render it again at 240x60, strip the borders,
compare the text. Any difference means the narrower rendering dropped
something.

That test would have caught `N` without anybody counting the hint's length, and
it catches the next one the same way.

## Three more dialogs with the same defect, differently

Writing the general gate turned up something the specific one could not.

The settings popup, the filter popup and the column selector all accept `Esc`
in their controllers. None of them said so anywhere on screen.

From the keyboard those are the same defect as `N`. A dialog that never names
its exit and a dialog that names it and cuts it off both leave the user
guessing, and guessing wrong in a modal dialog during a live capture is not a
small cost. All four now name their exit, and a test holds them to it.

## Enumerate the overlays by what makes them overlays

Earlier coverage missed the column selector, because it lives in
`src/tui/call_list.rs` rather than in the popup module, and the coverage table
read only the popup module.

The fix is to stop maintaining a table:

```rust
overlays += production.matches("frame.render_widget(Clear").count();
```

`render_widget(Clear, ..)` is what makes something an overlay, so counting that
call is the honest enumeration. A popup added anywhere under `src/tui/` shows
up as uncovered rather than quietly escaping the gate.

Two details in that scan are worth copying. It matches the **call** form rather
than the bare substring, because the prose in the same file explaining the rule
would otherwise count as an overlay — a scanner counting its own documentation
is measuring itself. And it reads only the production half of each file, since
the tests below render overlays too.

## Then the size sweep found two crashes

With every overlay enumerated, sweeping sizes became cheap. It produced two
panics.

The settings popup panicked below six rows. The filter popup panicked at sizes
as ordinary as **66x12**. Both computed their row positions from a constant
height, and `Buffer::set_string` panics on an out-of-bounds index.

A panic takes the whole TUI down mid-capture, and resizing a terminal is not an
error case.

The sweep is exhaustive on width for a reason:

```rust
for w in 1u16..=90 {
    for h in [1u16, 2, 3, 5, 8, 12, 20, 30] {
```

The two crashes sat at 4x3 and 66x12 — one absurd, one completely ordinary. No
sampled list of "sizes worth testing" would have held both. A sampler that
thought to include tiny terminals would have found the first and missed the
second, and one that thought to include realistic ones would have done the
reverse.

## Three directions on the fix

Every write across `src/tui/` now goes through `set_string_clipped`, which
declines rather than panicking and truncates at the right edge rather than
running into the border. Three gates hold it there.

The helper is correct on its own: out-of-bounds starts in every direction, a
zero-sized area, multibyte truncation.

Nothing bypasses it — a source gate, because calling `Buffer::set_string`
directly is the obvious thing to reach for and, as the test's own comment puts
it, is "what all 42 existing call sites did".

And every overlay survives the sweep.

The snapshot suite pins rendered frames character by character, and it is the
evidence that the clipping migration altered no rendering. Three snapshots
moved, and all three moved for the visible fix rather than the safety one — a
line appearing where a popup previously named no exit:

```diff
-            │                                                      │
+            │  Tab move · Enter apply · Esc cancel                 │
```

A safety change that quietly shifted a column would have shown up in the rest
of them.

## Worth stealing

A gate that needs to know your content is a gate you have to update whenever
the content changes. Look for the property that holds without knowing the
strings — here, "more room cannot reveal more text" — because that one keeps
working after everybody has forgotten it exists.

And enumerate a category by the thing that defines it, not by a list. The list
was right when somebody wrote it, and the item it was missing lived one file
over.
