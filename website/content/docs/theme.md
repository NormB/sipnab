+++
title = "Theme Customization"
description = "Customize sipnab's TUI colors with 11 semantic color slots. Includes Catppuccin, Nord, Solarized, and high-contrast presets."
weight = 6

[extra]
weight = 6
+++

sipnab's TUI uses 11 semantic color slots that control every visual element. Customize them via the `[theme]` section in your config file.

## Color Slots

| Slot | Default | What It Affects |
|------|---------|-----------------|
| `background` | `reset` (terminal default) | Terminal background color |
| `foreground` | `white` | Default text color |
| `header` | `cyan` | Status bar, column headers, endpoint labels in call flow |
| `selected` | `yellow` | Selected/highlighted row, cursor position, focused item |
| `accent` | `magenta` | Correlation info, PDD annotations, extended flow labels |
| `good` | `green` | Positive quality (MOS > threshold), success states (InCall, Registered) |
| `warning` | `yellow` | Medium quality, caution states (Ringing, CANCEL) |
| `bad` | `red` | Poor quality, failures, errors, high loss/jitter |
| `muted` | `dark_gray` | Separators, pipe characters, disabled text, timestamps |
| `border` | `white` | Widget borders, panel frames |
| `highlight` | -- | Legacy alias for `selected` (backward compatibility only) |

The internal `status_bg` color (dark blue-gray `#303040`) is not configurable and is used for the status bar background.

## Supported Color Syntax

### Named Colors

`black`, `white`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `gray` (or `grey`), `dark_gray` (or `dark_grey`, `darkgray`, `darkgrey`), `reset` (or `default`)

### Hex RGB

`"#RRGGBB"` format, e.g., `"#ff8800"`, `"#1a1a2e"`. Requires a terminal with true-color (24-bit) support.

## How to Apply

Create or edit your config file at one of these locations (searched in order):

1. Path specified via `--config <FILE>`
2. `$SIPNAB_CONFIG` environment variable
3. `~/.config/sipnab/sipnab.toml`
4. `~/.sipnabrc`
5. `/etc/sipnab/sipnab.toml`

Add a `[theme]` section with the color values you want to override. Omitted fields use the built-in defaults.

## Example Themes

### Dark (built-in default)

The built-in theme works on dark terminal backgrounds without any configuration.

```toml
[theme]
background = "reset"
foreground = "white"
header = "cyan"
selected = "yellow"
accent = "magenta"
good = "green"
warning = "yellow"
bad = "red"
muted = "dark_gray"
border = "white"
```

### Light Terminal

For light terminal backgrounds (white/cream). Uses darker colors for readability.

```toml
[theme]
background = "reset"
foreground = "black"
header = "blue"
selected = "#b35900"
accent = "#8b008b"
good = "#006400"
warning = "#b8860b"
bad = "#cc0000"
muted = "gray"
border = "dark_gray"
```

### Catppuccin Mocha

Pastel palette inspired by the Catppuccin color scheme.

```toml
[theme]
background = "#1e1e2e"
foreground = "#cdd6f4"
header = "#89b4fa"
selected = "#f9e2af"
accent = "#cba6f7"
good = "#a6e3a1"
warning = "#fab387"
bad = "#f38ba8"
muted = "#585b70"
border = "#6c7086"
```

### Nord

Low-contrast theme based on the Nord palette.

```toml
[theme]
background = "#2e3440"
foreground = "#d8dee9"
header = "#88c0d0"
selected = "#ebcb8b"
accent = "#b48ead"
good = "#a3be8c"
warning = "#ebcb8b"
bad = "#bf616a"
muted = "#4c566a"
border = "#616e88"
```

### Solarized Dark

```toml
[theme]
background = "#002b36"
foreground = "#839496"
header = "#268bd2"
selected = "#b58900"
accent = "#d33682"
good = "#859900"
warning = "#cb4b16"
bad = "#dc322f"
muted = "#586e75"
border = "#657b83"
```

### High Contrast

Maximum readability for accessibility or bright environments.

```toml
[theme]
background = "black"
foreground = "white"
header = "cyan"
selected = "#ffff00"
accent = "#ff00ff"
good = "#00ff00"
warning = "#ffaa00"
bad = "#ff0000"
muted = "gray"
border = "white"
```

## Tips

- Use `reset` for `background` to inherit your terminal's background color. This is usually the best choice.
- Hex colors require true-color terminal support (most modern terminals: iTerm2, Alacritty, kitty, WezTerm, Windows Terminal).
- Use `sipnab --dump-config` to verify your theme is being loaded.
- The `highlight` key is a legacy alias for `selected`. If both are set, `selected` takes precedence.
