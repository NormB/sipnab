+++
title = "Name the addresses of a call in the terminal interface"
date = 2026-09-01
updated = 2026-10-16
description = "Give host names to the IP addresses of a call from sipnab's call list, see the names replace the addresses, remove them again, and close any popup with Esc."

[extra]
kind = "howto"
+++

## In short

In sipnab's terminal interface, the call list shows each call's source and
destination as IP addresses. You can give an address a name, such as the name
of the server it belongs to:

- select a call and press `N`;
- type a name for each address and press Enter;
- the names replace the addresses in the call list, and sipnab keeps them for
  the next run.

Every popup in the interface says how to close it, and Esc closes all of them.

## Who this is for

Anyone reading calls in the terminal interface who finds IP addresses hard to
tell apart, for example on a capture taken between several servers.

## Open a capture

The examples use a capture from the sipnab repository:

```bash
sipnab -I tests/pcap-samples/sip-rtp-g711.pcap
```

The call list shows two calls between `10.0.2.20` and `10.0.2.15`.

## Name the two addresses of a call

Select a call and press `N`. The **Name Address** popup opens with the call's
two addresses. This is the popup on a terminal 100 columns wide:

```text
               ┌ Name Address ─────────────────────────────────────────────────────┐
               │  Endpoint:  10.0.2.20   10.0.2.15                                 │
               │  IP:   10.0.2.20                                                  │
               │  Name:                                                            │
               │                                                                   │
               │  Tab switch endpoint · Enter save all · empty clears · Esc cancel │
               └───────────────────────────────────────────────────────────────────┘
```

- Type a name for the first address, for example `pbx-a`.
- Press Tab to move to the second address, and type its name, for example
  `sbc-b`.
- Press Enter to save both.

The status line reports `Named 2 endpoints`, and the call list shows the
names:

```text
  # ▲    Method    From To   Source          Destination     State      Msgs +Prev    PDD    Duratio
> [ ] 1  INVITE    sipp test pbx-a           sbc-b           Completed  6    +0.000s         8.5s
  [ ] 2  INVITE    sipp test pbx-a           sbc-b           InCall     4    +8.619s         4ms
```

Naming an address turns name resolution on. sipnab saves the names to
`~/.config/sipnab/hosts` (`$XDG_CONFIG_HOME/sipnab/hosts`), one address and
name per line, so they apply the next time you open a capture:

```text
10.0.2.15	sbc-b
10.0.2.20	pbx-a
```

## Remove a name

Select the call and press `N` again. Each address shows its current name.

- Delete the name of each address you want to clear. Tab moves between them.
- Press Enter.

The status line reports `Cleared 2 names`, and the call list shows the
addresses again.

## Close a popup

Esc closes every popup without applying it. Each popup names its closing key
on its last line:

| Popup | Opened with | Last line |
|---|---|---|
| Name Address | `N` | `Tab switch endpoint · Enter save all · empty clears · Esc cancel` |
| Filter | F7 | `Tab move · Enter apply · Esc cancel` |
| Settings | F8 | `↑/↓ move · Enter toggle · Esc close` |
| Columns | F10 | `Space: toggle  Enter: apply  Esc: close` |

On a small terminal, sipnab draws as much of a popup as fits and keeps
running. On a terminal smaller than 40 columns by 6 rows, sipnab shows only
the notice `Terminal too small (<width>x<height>) — sipnab needs at least 40x6`
until you make the window larger.

## Terms used here

- **Terminal interface (TUI)**: sipnab's full-screen interactive view, opened
  by running `sipnab` without `-N`.
- **Popup**: a small window drawn over the main view for one task.
- **Endpoint**: one IP address taking part in a call.
- **Name resolution**: showing host names in place of IP addresses. Press `n`
  to cycle it between off, static names and reverse DNS.
- **`$XDG_CONFIG_HOME`**: the directory for per-user settings. When it is not
  set, it is `~/.config`.

## Related guides

- [Name resolution and the `N` popup](@/docs/keybindings.md#name-resolution)
- [Filter popup keys](@/docs/keybindings.md#filter-popup)
- [Settings popup keys](@/docs/keybindings.md#settings-popup)
- [Column selector keys](@/docs/keybindings.md#column-selector)
