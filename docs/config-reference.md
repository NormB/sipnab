# Config Reference

sipnab reads configuration from a TOML file. CLI flags override config file values.

## File Locations

Configuration is loaded from the first file found, in this order:

| Priority | Source |
|----------|--------|
| 1 | `--config <FILE>` (must exist, errors if missing) |
| 2 | `$SIPNAB_CONFIG` environment variable |
| 3 | `~/.config/sipnab/sipnab.toml` |
| 4 | `~/.sipnabrc` |
| 5 | `/etc/sipnab/sipnab.toml` |

Use `--no-config` (`-F`) to skip all file loading. Use `--dump-config` (`-D`) to print the effective configuration.

Unknown keys produce a warning and are ignored, allowing configs to be shared across versions.

## Format

Standard [TOML](https://toml.io/). All sections and keys are optional.

```toml
[capture]
device = "eth0"
portrange = "5060-5080"

[display]
color = "always"

[security]
kill_scanner = true
alert = ["syslog", "json"]
```

## Sections

### [capture]

Packet capture defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `device` | string | -- | Default network interface |
| `portrange` | string | `"5060-5061"` | SIP port range |
| `snaplen` | integer | OS default | Snapshot length in bytes |
| `buffer` | integer | OS default | Kernel capture buffer size in MiB |
| `no_rtp` | boolean | `false` | Disable RTP capture by default |

### [display]

Output and TUI display settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `color` | string | `"auto"` | Color mode: `"auto"`, `"always"`, `"never"` |
| `payload_limit` | integer | -- | Maximum payload bytes to display |
| `delta_time` | boolean | `false` | Show delta time between messages |

### [filter]

Default filter presets applied at startup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `from` | string | -- | Default From header filter (regex) |
| `to` | string | -- | Default To header filter (regex) |
| `expression` | string | -- | Default filter DSL expression |

### [security]

Security detection defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kill_scanner` | boolean | `false` | Enable scanner detection |
| `kill_response` | integer | `200` | SIP response code for scanner reports |
| `fraud_detect` | boolean | `false` | Enable fraud detection heuristics |
| `alert` | array of strings | `[]` | Alert channels: `"syslog"`, `"json"`, `"exec"` |
| `alert_exec` | string | -- | Command to execute on alert |

### [limits]

Resource limits to prevent unbounded memory growth.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dialog_limit` | integer | `100000` | Maximum tracked dialogs |
| `max_streams` | integer | `50000` | Maximum RTP streams |
| `max_reassembly` | integer | `10000` | Maximum TCP reassembly sessions |
| `hep_rate_limit` | integer | `50000` | Maximum HEP packets per second |

### [privilege]

Privilege separation settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user` | string | -- | User to drop privileges to after capture open |
| `no_priv_drop` | boolean | `false` | Disable privilege dropping |
| `chroot` | string | -- | Chroot directory after initialization |

### [theme]

TUI color theme. Values are CSS-style hex colors.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `background` | string | terminal default | Background color (e.g., `"#000000"`) |
| `foreground` | string | terminal default | Foreground color (e.g., `"#ffffff"`) |
| `highlight` | string | terminal default | Highlight/selection color (e.g., `"#ff0000"`) |

### [keybindings]

TUI key binding overrides.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `quit` | string | `"q"` | Key to quit |
| `help` | string | `"?"` | Key to show help |
| `filter` | string | `"/"` | Key to open filter prompt |

## Example

Full config with all sections:

```toml
[capture]
device = "eth0"
portrange = "5060-5080"
snaplen = 65535
buffer = 16
no_rtp = false

[display]
color = "always"
payload_limit = 4096
delta_time = true

[filter]
from = "^1001@"
to = "^1002@"
expression = "method == INVITE"

[security]
kill_scanner = true
kill_response = 403
fraud_detect = true
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/sipnab-alert.sh"

[limits]
dialog_limit = 50000
max_streams = 25000
max_reassembly = 5000
hep_rate_limit = 25000

[privilege]
user = "sipnab"
no_priv_drop = false
chroot = "/var/lib/sipnab"

[theme]
background = "#1a1a2e"
foreground = "#e0e0e0"
highlight = "#e94560"

[keybindings]
quit = "q"
help = "?"
filter = "/"
```
