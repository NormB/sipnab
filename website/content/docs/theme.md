+++
title = "Theme Guide"
weight = 6
description = "Customize sipnab's TUI colors with 11 semantic color slots and preset themes."
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

Each theme below includes a TOML config block and a live preview showing how it renders in sipnab's TUI.

### Default (Ayu Mirage)

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Default Theme</span>
</div>
<pre class="terminal-body" style="background:#0a0e14;color:#cbccc6"><span style="color:#707a8c">  #  Method     From           To             State</span>
<span style="color:#ffcc66">&#9656;</span> <span style="color:#d4bfff">1  INVITE     alice          bob            </span><span style="color:#bae67e">InCall</span>
  <span style="color:#d4bfff">2  REGISTER   admin          --             </span><span style="color:#bae67e">Registered</span>
  <span style="color:#d4bfff">3  INVITE     charlie        dave           </span><span style="color:#ffcc66">Ringing</span>
  <span style="color:#d4bfff">4  INVITE     +15551234      +15559876      </span><span style="color:#ff6666">Failed</span>
  <span style="color:#d4bfff">5  INVITE     1005           1006           </span><span style="color:#bae67e">Completed</span></pre>
</div>

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Catppuccin Mocha</span>
</div>
<pre class="terminal-body" style="background:#1e1e2e;color:#cdd6f4"><span style="color:#585b70">  #  Method     From           To             State</span>
<span style="color:#f9e2af">&#9656;</span> <span style="color:#cba6f7">1  INVITE     alice          bob            </span><span style="color:#a6e3a1">InCall</span>
  <span style="color:#cba6f7">2  REGISTER   admin          --             </span><span style="color:#a6e3a1">Registered</span>
  <span style="color:#cba6f7">3  INVITE     charlie        dave           </span><span style="color:#fab387">Ringing</span>
  <span style="color:#cba6f7">4  INVITE     +15551234      +15559876      </span><span style="color:#f38ba8">Failed</span>
  <span style="color:#cba6f7">5  INVITE     1005           1006           </span><span style="color:#a6e3a1">Completed</span></pre>
</div>

### Nord

Low-contrast theme based on the Nord palette. Easy on the eyes for long monitoring sessions.

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Nord</span>
</div>
<pre class="terminal-body" style="background:#2e3440;color:#d8dee9"><span style="color:#4c566a">  #  Method     From           To             State</span>
<span style="color:#ebcb8b">&#9656;</span> <span style="color:#b48ead">1  INVITE     alice          bob            </span><span style="color:#a3be8c">InCall</span>
  <span style="color:#b48ead">2  REGISTER   admin          --             </span><span style="color:#a3be8c">Registered</span>
  <span style="color:#b48ead">3  INVITE     charlie        dave           </span><span style="color:#ebcb8b">Ringing</span>
  <span style="color:#b48ead">4  INVITE     +15551234      +15559876      </span><span style="color:#bf616a">Failed</span>
  <span style="color:#b48ead">5  INVITE     1005           1006           </span><span style="color:#a3be8c">Completed</span></pre>
</div>

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Solarized Dark</span>
</div>
<pre class="terminal-body" style="background:#002b36;color:#839496"><span style="color:#586e75">  #  Method     From           To             State</span>
<span style="color:#b58900">&#9656;</span> <span style="color:#d33682">1  INVITE     alice          bob            </span><span style="color:#859900">InCall</span>
  <span style="color:#d33682">2  REGISTER   admin          --             </span><span style="color:#859900">Registered</span>
  <span style="color:#d33682">3  INVITE     charlie        dave           </span><span style="color:#cb4b16">Ringing</span>
  <span style="color:#d33682">4  INVITE     +15551234      +15559876      </span><span style="color:#dc322f">Failed</span>
  <span style="color:#d33682">5  INVITE     1005           1006           </span><span style="color:#859900">Completed</span></pre>
</div>

### Gruvbox Dark

Warm, retro-inspired color scheme.

```toml
[theme]
background = "#282828"
foreground = "#ebdbb2"
header = "#83a598"
selected = "#fabd2f"
accent = "#d3869b"
good = "#b8bb26"
warning = "#fe8019"
bad = "#fb4934"
muted = "#665c54"
border = "#7c6f64"
```

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Gruvbox Dark</span>
</div>
<pre class="terminal-body" style="background:#282828;color:#ebdbb2"><span style="color:#665c54">  #  Method     From           To             State</span>
<span style="color:#fabd2f">&#9656;</span> <span style="color:#d3869b">1  INVITE     alice          bob            </span><span style="color:#b8bb26">InCall</span>
  <span style="color:#d3869b">2  REGISTER   admin          --             </span><span style="color:#b8bb26">Registered</span>
  <span style="color:#d3869b">3  INVITE     charlie        dave           </span><span style="color:#fe8019">Ringing</span>
  <span style="color:#d3869b">4  INVITE     +15551234      +15559876      </span><span style="color:#fb4934">Failed</span>
  <span style="color:#d3869b">5  INVITE     1005           1006           </span><span style="color:#b8bb26">Completed</span></pre>
</div>

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Light Terminal</span>
</div>
<pre class="terminal-body" style="background:#f5f5f0;color:#1a1a1a"><span style="color:#999999">  #  Method     From           To             State</span>
<span style="color:#b35900">&#9656;</span> <span style="color:#8b008b">1  INVITE     alice          bob            </span><span style="color:#006400">InCall</span>
  <span style="color:#8b008b">2  REGISTER   admin          --             </span><span style="color:#006400">Registered</span>
  <span style="color:#8b008b">3  INVITE     charlie        dave           </span><span style="color:#b8860b">Ringing</span>
  <span style="color:#8b008b">4  INVITE     +15551234      +15559876      </span><span style="color:#cc0000">Failed</span>
  <span style="color:#8b008b">5  INVITE     1005           1006           </span><span style="color:#006400">Completed</span></pre>
</div>

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

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">High Contrast</span>
</div>
<pre class="terminal-body" style="background:#000000;color:#ffffff"><span style="color:#999999">  #  Method     From           To             State</span>
<span style="color:#ffff00">&#9656;</span> <span style="color:#ff00ff">1  INVITE     alice          bob            </span><span style="color:#00ff00">InCall</span>
  <span style="color:#ff00ff">2  REGISTER   admin          --             </span><span style="color:#00ff00">Registered</span>
  <span style="color:#ff00ff">3  INVITE     charlie        dave           </span><span style="color:#ffaa00">Ringing</span>
  <span style="color:#ff00ff">4  INVITE     +15551234      +15559876      </span><span style="color:#ff0000">Failed</span>
  <span style="color:#ff00ff">5  INVITE     1005           1006           </span><span style="color:#00ff00">Completed</span></pre>
</div>

## Tips

- Use `reset` for `background` to inherit your terminal's background color. This is usually the best choice.
- Hex colors require true-color terminal support (most modern terminals: iTerm2, Alacritty, kitty, WezTerm, Windows Terminal).
- Use `sipnab --dump-config` to verify your theme is being loaded.
- The `highlight` key is a legacy alias for `selected`. If both are set, `selected` takes precedence.
