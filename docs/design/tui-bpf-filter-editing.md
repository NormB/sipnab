# Editing the capture filter from the TUI, and showing it honestly

**Norm, 2026-09-14:** "when the TUI is started the BPF filter is a very long
string that is always cut off. Recommend an approach to shorten it or not
display it at all. Consider the BPF filter field being made similar to the
search field so that if it is changed, the new BPF filter replaces the current
one, and a checkbox can add the new filter to the currently running one."

This spec gates the implementation. It covers two problems the operator meets in
one place — a filter shown so long it reads as a mistake, and a filter an
operator cannot change without restarting — and keeps them apart, because one is
a rendering fix and the other adds a capability.

## The two problems, kept apart

1. **Display.** `sipnab -d eth0` compiles a generated capture filter: one
   portrange arm for SIP and RTP, plus one encapsulation arm per link-header and
   tunnel-depth offset. It runs well over a thousand columns. Status line 2
   already cuts it with an ellipsis rather than a silent clip
   (`fit_bpf_to_cols` in [`src/tui/render/status.rs`](https://github.com/NormB/sipnab/blob/main/src/tui/render/status.rs)), because a filter clipped to
   look complete "says it does less than it does". The ellipsis is honest but
   unhelpful — the operator reads a meaningless prefix and learns nothing.
2. **No runtime control.** The filter is compiled once, at capture open
   ([`src/capture/live.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs) for a live device, [`src/capture/file.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs) for a replay).
   An operator who wants the kernel to capture more, or less, has to stop sipnab,
   edit the command line, and start again — losing every dialog on screen.

## What the filter actually is, so the design does not lie about it

The effective BPF expression is `scaffolding(selection)`: the tunnel and
encapsulation arms that let sipnab see SIP inside GTP-U, VXLAN and stacked link
headers, wrapped around a selection of what to match. The operator authors the
selection. The scaffolding is generated and is the part nobody wants to read.

This matters for one reason above all: a naive "replace the whole string" would
let an operator who types `host 192.0.2.5` silently drop every tunnel arm, so
tunneled SIP would vanish with no error. **The operator edits the selection.
sipnab always re-wraps it in the scaffolding.** The scaffolding is never
something the operator types or deletes by accident.

The capture filter is also NOT the display filter. `F7` already opens a display
filter — which dialogs the operator sees, applied after capture. The BPF filter
decides which packets the kernel hands sipnab at all. The design keeps the two
visibly distinct, or an operator conflates "I stopped seeing it" with "it was
never captured".

## The display

Status line 2 renders the BPF slot three ways:

- **The generated default** renders as a compact label, not the expression:
  `BPF Filter: default (SIP + RTP, all encapsulations)`. sipnab knows the filter
  is the default because it generated it, so this is a fact it holds rather than
  a guess from the text.
- **An operator's own filter** — supplied on the command line or typed in the
  editor — renders verbatim, since it is short. It keeps today's ellipsis only
  when it genuinely overflows the row.
- **A key (proposed `B`)** opens the editor, and the editor always shows the full
  effective expression. So the summary and the ellipsis are never a dead end:
  the full text is one keystroke away, not only on a startup log line the
  operator has to scroll back to.

## The editor

`B` opens the full-filter popup (implemented); a later increment turns it into
an append editor, modeled on the search input the TUI already has:

- A text input where the operator types an expression to combine with the
  running filter, with an **AND | OR** toggle. AND narrows — the kernel captures
  only packets matching both. OR widens — it captures packets matching either.
- Append operates on the WHOLE current effective filter: AND yields
  `(current) and (typed)`, OR yields `(current) or (typed)`. Because "current"
  already contains the tunnel scaffolding, append preserves it — the operator
  cannot drop tunnel handling by appending.
- `Enter` applies (validating first). `Esc` cancels and leaves the running
  filter untouched.
- As the operator types, the editor renders the full effective expression the
  apply will compile, so what runs is visible before it runs.

**v1 is append-only; Replace is deferred.** See the implementation finding
below: the generated default's port selection is woven THROUGH its tunnel arms,
so there is no separable "selection" to replace and re-wrap. Replace-on-the-
default needs a design decision — refuse it, replace-the-whole-filter with a
warning that tunnel handling is dropped, or regenerate the scaffolding — that a
later version settles. Append is always correct and ships first (Norm chose
append-only v1, 2026-09-14).

## The filter model, as pure functions

Two pure functions carry the rule, so the composition is tested without a
terminal or a capture and cannot drift between the surfaces that call it:

- `compose_selection(current, new, mode) -> selection`. Replace returns `new`.
  Append-AND returns `(current) and (new)`. Append-OR returns `(current) or
  (new)`. The parentheses are not optional — BPF binds `and` tighter than `or`,
  and an un-parenthesized append changes meaning the moment the operator's
  expression contains either word.
- `wrap_in_scaffolding(selection) -> effective_bpf`. The single place the tunnel
  arms are applied, reused by capture open and by a runtime change, so the two
  cannot generate different filters from the same selection.

Every apply **validates before it changes anything**: sipnab compiles the
effective expression first, and on a compile error it shows the compiler's own
message and leaves the running filter exactly as it was. A typo never takes the
capture down.

## Implementation status and a finding that reshapes the model

Landed so far (in their own commits, all CI-green, not yet released):

- `compose_selection` — [`src/capture/bpf_filter.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/bpf_filter.rs), the Replace/AppendAnd/AppendOr core, TDD'd and mutation-verified.
- The status-bar summary of the generated default, and the `B` popup showing the
  full expression verbatim (both wired through the App and the exhaustive view
  matches).

**The finding that reshapes `wrap_in_scaffolding`.** Reading
[`auto_bpf_filter`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs) shows the generated default is NOT `scaffolding(selection)` with a
separable selection. It is three OR-ed arms — an untagged `portrange`, a tunnel
arm `((ether proto …) and (ip_and_ports_at(offset, lo, hi) or …))`, and per-port
opt-in arms — and the port selection `lo,hi` is woven THROUGH the tunnel arm's
per-offset tests, not wrapped around a decomposable inner expression. So there
is no "selection" to extract and re-wrap for the default, and
`wrap_in_scaffolding(selection)` as written above cannot be built for it.

What this changes:

- **Append is unaffected and always correct**: it operates on the WHOLE current
  effective filter (`(current) and/or (typed)`), so the scaffolding, being
  inside `current`, is preserved. This is what v1 ships.
- **Replace on the generated default is deferred** — it is the only case that
  needed `wrap_in_scaffolding`, and the decision between refuse / warn-and-drop /
  regenerate is left to a later version.
- An operator-supplied filter has no scaffolding (it is used as-is at capture
  open), so for it "the current filter" simply IS the operator's expression, and
  both append and a future replace are straightforward.

## Runtime re-apply

The capture runs on its own thread and the TUI on another. A change travels from
the editor to the capture thread over a channel, and the two capture sources
answer it differently:

- **Live.** The capture thread compiles the new effective expression and calls
  `pcap_setfilter` on its live handle. libpcap applies it to packets from that
  point on. It cannot un-capture a packet already delivered or reach back for one
  the old filter dropped, so **the change affects capture going forward** and the
  dialogs already on screen stay. The apply prints one line saying so:
  "filter changed; applies to new packets". (Rejected alternative: tearing the
  capture down and restarting it with the new filter — heavier, and it discards
  in-flight reassembly and correlation state for no gain over `pcap_setfilter`.)
- **File.** A replay has no "going forward" — the packets are all on disk. A
  change re-reads the file from the start under the new filter, which clears the
  dialog store and rebuilds it. The apply says "re-scanning with new filter" so
  the operator reads the pause as a re-scan, not a hang, and never mistakes it
  for the live case.

## Testing

- **Pure, driven directly:** `compose_selection` across Replace, Append-AND and
  Append-OR, including the parenthesization that keeps `or` from swallowing an
  append. `wrap_in_scaffolding` over a selection with and without tunnel arms.
  The validate-or-reject rule: a malformed expression returns the compiler error
  and signals no change.
- **The re-apply seam:** the capture-thread reconfigure entry point talks to
  libpcap, so its conversion — a new selection to a compiled, applied filter — is
  tested against an injected handle, and the test records why the live wire is
  unreachable from a unit test.
- **The editor state machine:** enter, type, toggle Replace/Append, toggle
  AND/OR, apply, cancel — tested at its pure core, the way the TUI's other
  dialogs are, without a live terminal.

## Scope and non-goals

- **In:** the display summary, the editor, replace and append with an AND/OR
  toggle, live re-apply and file re-scan, validate-before-apply, the full
  expression on demand.
- **Out (YAGNI, v1):** saved filter presets or profiles, a filter history ring,
  and any auto-suggestion of expressions. The operator types BPF and sipnab
  runs it or rejects it.

## The one risk worth naming

The file re-scan — clearing and rebuilding the dialog store mid-run — is the
heaviest piece and the one most likely to surface edge cases: an export in
progress, the selection cursor pointing at a dialog the re-scan drops, a filter
that now matches nothing. The live path is the clean one. The implementation
plan sequences the live path first and treats the file re-scan as its own step
with its own tests, so the risky half is isolated and can be verified on its own.
