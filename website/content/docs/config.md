+++
title = "Config Reference"
weight = 10
description = "TOML configuration file format and all configurable sections."
+++

> **Quick start:** Config is optional. sipnab works with zero configuration out of the box. Use a config file to set persistent defaults for your environment.

## Minimal Config

If you only need to override a few defaults, keep it short:

```toml
# ~/.config/sipnab/sipnab.toml
[capture]
device = "eth0"

[display]
delta_time = true

[theme]
background = "#1e1e2e"
foreground = "#cdd6f4"
```

sipnab reads configuration from a TOML file. CLI flags always override config file values.

## File Locations

Configuration is loaded from the first file found in this order:

| Priority | Source |
|----------|--------|
| 1 | `--config <FILE>` (must exist; errors if missing) |
| 2 | `$SIPNAB_CONFIG` environment variable |
| 3 | `~/.config/sipnab/sipnab.toml` |
| 4 | `~/.sipnabrc` |
| 5 | `/etc/sipnab/sipnab.toml` |

Use `--no-config` (`-F`) to skip all file loading. Use `--dump-config` (`-D`) to print the effective merged configuration.

Unknown keys produce a warning and are ignored, allowing configs to be shared across versions.

## Format

Standard [TOML](https://toml.io/). All sections and keys are optional. Only set values you want to change from defaults.

## Sections

### \[capture\]

Packet capture defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `device` | string | -- | Default network interface |
| `portrange` | string | `"5060-5061"` | SIP port range |
| `snaplen` | integer | `65535` | Snapshot length in bytes |
| `buffer` | integer | `2` | Kernel capture buffer size in MiB |
| `buffer_budget_mb` | integer | `64` | Memory budget for the in-flight capture→processing queue (grows under load up to this, capped; shrinks when idle). `--buffer-budget` overrides |
| `promisc` | boolean | `true` | Put a named interface into promiscuous mode (the `any` device is never promiscuous). `--no-promisc` overrides this to `false` |
| `no_rtp` | boolean | `false` | Disable RTP capture by default |

```toml
[capture]
device = "eth0"
portrange = "5060-5080"
snaplen = 65535
buffer = 16
promisc = true
no_rtp = false
```

### \[sip\]

SIP protocol handling.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `xcid_headers` | array | `["X-Call-ID"]` | Header names used to correlate B2BUA call legs (sngrep `sip.xcid`). A dialog whose message carries one of these headers pointing at another dialog's Call-ID is correlated. Add carrier-specific headers here; an empty/unset list keeps the `X-Call-ID` default |

```toml
[sip]
xcid_headers = ["X-Call-ID", "X-CID"]
```

### \[display\]

Output and TUI display settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `color` | string | `"auto"` | Color mode: `"auto"`, `"always"`, `"never"` |
| `payload_limit` | integer | -- | Maximum payload bytes to display |
| `delta_time` | boolean | `false` | Show delta time between messages by default |
| `from_to` | string | `"default"` | From/To column display: `"default"` (user else host:port), `"host-port"`, `"user"`, `"user-host-port"`. Cycle at runtime with `u`; `--from-to-mode` overrides |
| `visible_columns` | array of strings | all columns | Columns to display in the Call List (persisted across sessions). Values (case-insensitive): `"#"`, `"method"`, `"from"`, `"to"`, `"source"`, `"destination"`, `"state"`, `"msgs"`, `"date"`, `"pdd"`, `"duration"` |

```toml
[display]
color = "always"
payload_limit = 4096
delta_time = true
visible_columns = ["method", "from", "to", "source", "destination", "state", "msgs", "pdd"]
```

### \[filter\]

Default filter presets applied at startup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `from` | string | -- | Default From header filter (regex) |
| `to` | string | -- | Default To header filter (regex) |
| `expression` | string | -- | Default filter DSL expression |

```toml
[filter]
from = "^1001@"
to = "^1002@"
expression = "method == 'INVITE'"
```

### \[security\]

Security detection defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kill_scanner` | boolean | `false` | Enable scanner detection |
| `kill_response` | integer | `200` | SIP response code for scanner reports (100-699) |
| `fraud_detect` | boolean | `false` | Enable fraud detection heuristics |
| `alert` | array of strings | `[]` | Alert channels: `"syslog"`, `"json"`, `"exec"` |
| `alert_exec` | string | -- | Command to execute on alert |

```toml
[security]
kill_scanner = true
kill_response = 403
fraud_detect = true
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/sipnab-alert.sh"
```

### \[limits\]

Resource limits to prevent unbounded memory growth.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dialog_limit` | integer | `100000` | Maximum tracked dialogs |
| `max_streams` | integer | `50000` | Maximum RTP streams |
| `max_reassembly` | integer | `10000` | Maximum TCP reassembly sessions |
| `hep_rate_limit` | integer | `50000` | Maximum HEP packets per second |
| `max_header_line` | integer | `8192` | Maximum bytes in a single SIP header (defense-in-depth) |
| `max_headers_per_message` | integer | `200` | Maximum SIP headers per message (defense-in-depth) |
| `max_messages_per_dialog` | integer | `500` | Maximum stored messages per dialog (defense-in-depth) |
| `max_audio_frames` | integer | `1500` | Maximum RTP payload frames stored per stream for WAV export (~30s at G.711 50pps) |

```toml
[limits]
dialog_limit = 50000
max_streams = 25000
max_reassembly = 5000
hep_rate_limit = 25000
max_header_line = 8192
max_headers_per_message = 200
max_messages_per_dialog = 500
max_audio_frames = 1500
```

### \[privilege\]

Privilege separation settings (Linux only).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user` | string | `"nobody"` | User to drop privileges to after opening capture devices |
| `no_priv_drop` | boolean | `false` | Disable privilege dropping |
| `chroot` | string | -- | Chroot directory after initialization |

```toml
[privilege]
user = "sipnab"
no_priv_drop = false
chroot = "/var/lib/sipnab"
```

### \[crash\]

What happens when sipnab panics: the panic hook restores the terminal, writes a crash report, and then either exits cleanly or aborts so the OS can produce a core dump.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reports` | boolean | `true` | Write a crash-report file on panic (message, location, thread, version, backtrace) |
| `backtrace` | boolean | `true` | Capture a full backtrace in the report (independent of `RUST_BACKTRACE`) |
| `report_dir` | string | `~/.local/state/sipnab` | Directory crash reports (`sipnab-crash-<timestamp>-<pid>.log`) are written to |
| `core` | boolean | `false` | `true`: abort after the report so the kernel can dump core (subject to `ulimit -c` / `core_pattern`); `false`: exit cleanly with status 101, suppressing the core |

```toml
[crash]
reports = true
backtrace = true
report_dir = "/var/log/sipnab"
core = false
```

### \[names\]

Address name-resolution settings (display `host:port` instead of `ip:port`).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `false` | Start with name resolution on (offline sources) |
| `reverse_dns` | boolean | `false` | Also use reverse DNS (PTR) lookups |
| `hosts_file` | string | -- | `/etc/hosts`-format file of IP → name mappings to preload |
| `persist_to_config` | boolean | `false` | When set, in-TUI `N` edits are also written into the `[names.manual]` table below, preserving the rest of this file |
| `manual` | table | -- | Inline `"IP" = "name"` mappings, loaded at startup (highest-priority manual layer) |

```toml
[names]
enabled = true
reverse_dns = false
hosts_file = "/etc/sipnab/hosts"
persist_to_config = true

# Inline mappings (also written here when persist_to_config = true):
[names.manual]
"192.0.2.1" = "sbc-edge"
"2001:db8::1" = "core6"
```

### \[theme\]

TUI color theme with 11 semantic color slots (plus `highlight`, a legacy alias for `selected`). A few representative keys:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `background` | string | `"reset"` (terminal default) | Terminal background |
| `foreground` | string | `"white"` | Default text color |
| `good` | string | `"green"` | Positive quality, success states (InCall, Registered) |
| `bad` | string | `"red"` | Poor quality, failures, errors |

See the [Theme Guide](@/docs/theme.md) for the full slot table, supported color syntax, and preset themes.

```toml
[theme]
background = "#1a1a2e"
foreground = "#e0e0e0"
header = "cyan"
selected = "#e94560"
accent = "magenta"
good = "green"
warning = "yellow"
bad = "red"
muted = "dark_gray"
border = "#444466"
```

### \[keybindings\]

TUI key binding overrides for the 11 configurable actions. A few representative keys:

Accepted key formats:
- Single characters: `"q"`, `"/"`, `"A"`
- Function keys: `"F1"` through `"F12"`
- Special names: `"Esc"`, `"Space"`, `"Enter"`, `"Tab"`, `"Backspace"`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `quit` | string | `"q"` | Quit the application |
| `help` | string | `"F1"` | Show help overlay |
| `filter` | string | `"F7"` | Open filter dialog |
| `save` | string | `"F2"` | Open save capture dialog |

See [Keybindings](@/docs/keybindings.md) for the full shortcut reference and the complete list of configurable actions (the TOML example below shows all 11 with their defaults).

```toml
[keybindings]
quit = "q"
help = "F1"
filter = "F7"
save = "F2"
search = "/"
settings = "F8"
pause = "p"
autoscroll = "A"
extended_flow = "F4"
clear_calls = "F5"
column_selector = "F10"
```

## Full Example

A production-ready configuration for a SIP monitoring server:

```toml
# /etc/sipnab/sipnab.toml
# Production SIP monitoring configuration

# -- Packet capture --
[capture]
device = "eth0"                    # Primary SIP-facing interface
portrange = "5060-5080"            # Cover SIP, SIP-TLS, and alternate ports
snaplen = 65535                    # Full packet capture (no truncation)
buffer = 32                        # 32 MiB kernel buffer for burst tolerance
no_rtp = false                     # RTP analysis enabled

# -- Display settings --
[display]
color = "always"                   # Force color even when piped
payload_limit = 8192               # Show up to 8K of SIP body (large SDP)
delta_time = true                  # Show timing between messages by default
# visible_columns = ["method", "from", "to", "state", "msgs", "pdd"]  # Persistent column prefs

# -- Default filter (optional) --
[filter]
expression = "method == 'INVITE' OR method == 'REGISTER'"

# -- Security detection --
[security]
kill_scanner = true                # Detect SIP scanners (sipvicious, etc.)
fraud_detect = true                # Heuristic fraud detection
alert = ["syslog", "json"]        # Send alerts to syslog and JSON log
alert_exec = "/usr/local/bin/sipnab-alert.sh"  # Custom alert handler

# -- Resource limits --
[limits]
dialog_limit = 50000               # Max tracked dialogs (tune for RAM)
max_streams = 25000                # Max RTP streams
max_reassembly = 5000              # Max TCP reassembly sessions
hep_rate_limit = 25000             # Max HEP packets/sec

# -- Privilege separation (Linux) --
[privilege]
user = "sipnab"                    # Drop to unprivileged user after device open

# -- Theme: Catppuccin Mocha --
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

# -- Keybindings (defaults shown) --
[keybindings]
quit = "q"
help = "F1"
filter = "F7"
save = "F2"
search = "/"
settings = "F8"
pause = "p"
autoscroll = "A"
extended_flow = "F4"
clear_calls = "F5"
column_selector = "F10"
```

> **Tip:** Use `sipnab --dump-config` to see the effective configuration — the loaded file merged over the built-in defaults, with the path it came from. It is a config-file view only: CLI flags are applied later in startup and are *not* reflected, and there is no environment-variable override layer (`SIPNAB_CONFIG` only selects which file is read). To check what a flag does, compare against the [CLI reference](@/docs/cli.md).
