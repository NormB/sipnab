# Config reference

sipnab reads configuration from a TOML file. CLI flags ([cli-reference.md](cli-reference.md)) always override config file values.

Configuration is optional: with no file present sipnab runs on its built-in defaults. A config file exists to set persistent defaults for your environment.

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

## File Locations

sipnab reads configuration from the first file it finds in this order:

| Priority | Source |
|----------|--------|
| 1 | `--config <FILE>` (must exist; errors if missing) |
| 2 | `$SIPNAB_CONFIG` environment variable |
| 3 | `~/.config/sipnab/sipnab.toml` |
| 4 | `~/.sipnabrc` |
| 5 | `/etc/sipnab/sipnab.toml` |

Use `--no-config` (`-F`) to skip all file loading. Use `--dump-config` (`-D`) to print which file sipnab loaded and the keys it set — see the note under [Full example](#full-example) for what `-D` does and does not show.

Unknown keys produce a warning and go no further, so one config can span versions.

## Format

Standard [TOML](https://toml.io/). All sections and keys are optional. Only set values you want to change from defaults.

## Sections

<!-- Each section below is headed by the literal TOML table a user types into
sipnab.toml, so the first "word" is a lowercase identifier and sentence case
cannot be satisfied: "## Capture" would document a table that does not exist.
An exceptions entry cannot express this -- see .vale/styles/sipnab/Headings.yml. -->
<!-- vale sipnab.Headings = NO -->

### [capture]

Packet capture defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `device` | string | -- | Default network interface |
| `node_name` | string | hostname | Name this box reports as, in `capture_identity.node` on every MCP and REST answer. Lets an agent querying several servers tell WHICH one saw a given fact. `--node-name` overrides it, so a deployed config can name the box while a one-off command relabels it. The default puts the hostname on the wire. Clipped to 64 characters |
| `portrange` | string | `"5060-5061"` | SIP **signalling** port range; media is never gated by it. sipnab skips any SIP message with both ports outside the range, and a skipped message reaches no count, no dialog and no output — so this key decides how much of a capture you analyse at all. Widen it (`"1-65535"`) unless you know every port in play. `--portrange` overrides it |
| `snaplen` | integer | `65535` | Snapshot length in bytes |
| `buffer` | integer | `64` | Kernel capture buffer size in MiB (per device) |
| `buffer_budget_mb` | integer | `64` | Memory budget for the in-flight capture→processing queue. Grows under load up to this budget (capped, never OOM) and shrinks when idle. `--buffer-budget` overrides it |
| `no_rtp` | boolean | `false` | Disable RTP capture by default |
| `promisc` | boolean | `true` | Put a named interface into promiscuous mode (the `any` device is never promiscuous). `--no-promisc` overrides this to `false` |

```toml
[capture]
device = "eth0"
portrange = "5060-5080"
snaplen = 65535
buffer = 16
buffer_budget_mb = 64
no_rtp = false
promisc = true
```

### [display]

Output and TUI display settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `color` | string | `"auto"` | Color mode: `"auto"`, `"always"`, `"never"` |
| `payload_limit` | integer | -- | Maximum payload bytes to display |
| `delta_time` | boolean | `false` | Show delta time between messages by default |
| `from_to` | string | `"default"` | From/To column display: `"default"` (user else host:port), `"host-port"`, `"user"`, `"user-host-port"`. Cycle at runtime with `u`; `--from-to-mode` overrides this |
| `visible_columns` | array of strings | all columns | Call-list columns to show, by name (case-insensitive): `"#"`, `"Method"`, `"From"`, `"To"`, `"Source"`, `"Destination"`, `"State"`, `"Msgs"`, `"Date"`, `"PDD"`, `"Duration"`. Adjust at runtime with F10; `s` in the column selector writes the layout back to your sipnabrc, so it persists across sessions |

```toml
[display]
color = "always"
payload_limit = 4096
delta_time = true
from_to = "user-host-port"
visible_columns = ["method", "from", "to", "source", "destination", "state", "msgs", "pdd"]
```

### [filter]

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

### [sip]

SIP protocol handling.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `xcid_headers` | array | `["X-Call-ID"]` | Header names used to correlate B2BUA call legs (sngrep `sip.xcid`). A dialog whose message carries one of these headers pointing at another dialog's Call-ID joins that dialog. Add carrier-specific headers here; an empty/unset list keeps the `X-Call-ID` default |

```toml
[sip]
xcid_headers = ["X-Call-ID", "X-CID"]
```

### [security]

Security detection defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kill_scanner` | boolean | `false` | Enable scanner detection |
| `kill_response` | integer | `200` | SIP response code for scanner reports (100-699) |
| `fraud_detect` | boolean | `false` | Enable fraud detection heuristics |
| `alert` | array of strings | `[]` | Alert channels: `"syslog"`, `"json"`, `"exec"` |
| `alert_exec` | string | -- | Command to execute on alert |
| `reg_flood_threshold` | integer | `50` | REGISTER requests per second from one source before `--reg-flood` reports a flood. The default is a carrier-registrar figure: it never sees the ten-a-second brute force a small PBX gets, and it fires all through a re-REGISTER storm on a registrar that just restarted. `--reg-flood-threshold` overrides it. `0` fails validation and names the key |
| `kill_rate_limit` | integer | `10` | Scanner-kill responses per second sipnab may put on the wire. This bounds the one feature that transmits, and whoever forged the source address chose where each response goes, so there is no unlimited setting and `0` fails validation. A per-destination cap of 3 per minute applies underneath, so raising this widens how many distinct hosts sipnab answers, never how hard it hits one. `--kill-rate-limit` overrides it |
| `business_hours` | string | -- | Business hours as `"START-END"` in whole UTC hours, for example `"8-18"`. A wrapping range such as `"22-6"` is the overnight window. This is what makes the off-hours fraud detection reachable: with no window declared there is no outside for a call to fall in. `--business-hours` overrides it |
| `fraud_short_call_secs` | integer | `3` | Measured call duration below which `--fraud-detect` counts a completed call as short for wangiri detection. Three seconds is under a normal ring-no-answer on some carriers, which reports ordinary unanswered calls as lures. `--fraud-short-call` overrides it |
| `fraud_wangiri_calls` | integer | `3` | Short calls to one destination prefix before `--fraud-detect` reports wangiri. `--fraud-wangiri-calls` overrides it |
| `fraud_sequential_calls` | integer | `3` | Consecutive refused numbers before `--fraud-detect` reports sequential scanning. `--fraud-sequential-calls` overrides it |
| `fraud_volume_multiplier` | integer | `5` | Multiple of a source's own baseline call rate that `--fraud-detect` reports as a volume spike. `--fraud-volume-multiplier` overrides it |
| `fraud_volume_min_calls` | integer | `6` | Calls a source must place inside the volume window before `--fraud-detect` reports a spike at all. `--fraud-volume-min-calls` overrides it |
| `findings_history` | integer | `1000` | Security findings kept in memory for later retrieval. `0` keeps none, which is a real setting rather than a mistake. `--findings-history` overrides it |

```toml
[security]
kill_scanner = true
kill_response = 403
kill_rate_limit = 10
fraud_detect = true
business_hours = "8-18"
fraud_short_call_secs = 2
reg_flood_threshold = 10
findings_history = 5000
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/sipnab-alert.sh"
```

### [diagnosis]

Thresholds the signalling and media checks compare against. A number here
decides whether a call that is working gets reported as broken, so the defaults
are standards figures and a network that knows its own numbers beats a
recommendation written for the general case. Every value must be a finite
number greater than zero, and a value that is not fails validation and names
the key.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `post_dial_delay_secs` | float | `11.0` | Post-dial delay over which sipnab reports a call as slow, in seconds. The default is the ITU-T E.721 Table 2 target that 95 percent of international connections must meet, because a capture does not say which kind of call it holds. Tighten it to 8.0 for toll or 6.0 for local traffic. `--pdd-threshold` overrides it |
| `ack_timeout_secs` | float | `32.0` | Seconds a `2xx` may go unacknowledged before the missing `ACK` counts as a fault rather than as a capture that stopped early. The default is [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) Timer H. `--ack-timeout` overrides it |
| `no_final_response_secs` | float | `180.0` | Seconds an `INVITE` may sit without a final response before the silence gets reported. The default is RFC 3261 Timer C. Below it, every call still ringing when the capture stopped gets reported. `--no-final-response-timeout` overrides it |
| `duration_asymmetry_pct` | float | `5.0` | Percentage difference between the two legs' durations that counts as asymmetric. Must be 100 or less. `--duration-asymmetry-pct` overrides it |
| `duration_asymmetry_secs` | float | `2.0` | Absolute difference between the two legs' durations that counts as asymmetric, in seconds. A call has to clear both this and the percentage, so raising either one alone quiets the detection. `--duration-asymmetry-secs` overrides it |
| `late_media_ms` | integer | `500` | Milliseconds after the `200 OK` that media may start before it gets reported as late. `--late-media-ms` overrides it |

```toml
[diagnosis]
post_dial_delay_secs = 6.0
ack_timeout_secs = 32.0
no_final_response_secs = 180.0
duration_asymmetry_pct = 5.0
duration_asymmetry_secs = 2.0
late_media_ms = 500
```

## `[media]`

Properties of the observed media path that a passive tap cannot measure for
itself.

| Key | Type | Default | Description |
|---|---|---|---|
| `one_way_delay_ms` | float | -- | One-way network path delay in milliseconds, feeding the delay term of every MOS. The single MOS input no observer can measure from the wire: only the endpoints and you have it. A declared value beats an RTCP-reported round trip, because no packet can rewrite a config file; with neither, sipnab assumes 100 ms and labels the figure `assumed` rather than presenting it as measured |

### [limits]

Resource limits to prevent unbounded memory growth.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dialog_limit` | integer | `100000` | Maximum tracked dialogs |
| `mcp_max_rows` | integer | `1000` | Maximum rows in ONE list-style MCP response. Distinct from `dialog_limit` above, which bounds the whole run; these differ by 100x and bound different things. `0` fails validation and names the key |
| `max_streams` | integer | `50000` | Maximum RTP streams |
| `max_reassembly` | integer | `10000` | Maximum TCP reassembly sessions |
| `hep_rate_limit` | integer | `50000` | Maximum HEP packets per second |
| `max_header_line` | integer | `8192` | Maximum bytes in a single SIP header (defense-in-depth) |
| `max_headers_per_message` | integer | `200` | Maximum SIP headers per message (defense-in-depth) |
| `max_messages_per_dialog` | integer | `500` | Maximum stored messages per dialog (defense-in-depth) |
| `idle_compact_after_secs` | integer | `600` | Seconds of silence before sipnab compacts a dialog's stored messages. `0` fails validation and names the key |
| `keep_messages_per_idle_dialog` | integer | `20` | Messages an idle dialog keeps after compaction |
| `max_audio_frames` | integer | `1500` | Maximum RTP payload frames stored per stream for WAV export (~30s at G.711 50pps) |
| `lint_max_per_rule` | integer | `25` | Findings one lint rule may report for one dialog. A dialog that retransmits an `INVITE` eleven times trips a message rule eleven times and every one of them is true, so this decides whether the other rules stay readable underneath. `--lint-max-per-rule` overrides it. `0` fails validation and names the key |

```toml
[limits]
dialog_limit = 50000
max_streams = 25000
max_reassembly = 5000
hep_rate_limit = 25000
max_header_line = 8192
max_headers_per_message = 200
max_messages_per_dialog = 500
idle_compact_after_secs = 600
keep_messages_per_idle_dialog = 20
max_audio_frames = 1500
```

The last two are the only limits that discard data sipnab already captured.
Every other key here refuses to take something in. Compaction shortens a ladder
already in memory, so a call that went quiet shows fewer messages than crossed
the wire. sipnab warns once per run when this first happens.

Raise both when the ladder matters more than the footprint — a call parked on
hold, a dialog waiting on a slow PSTN leg, or a capture you paused all go quiet
for longer than ten minutes while still being the thing under investigation:

```toml
[limits]
idle_compact_after_secs = 3600
keep_messages_per_idle_dialog = 500
```

### [privilege]

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

### [names]

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

### [crash]

What happens when sipnab panics: the panic hook restores the terminal
(release builds abort without unwinding, so raw mode / mouse capture would
otherwise stay on), writes a crash report, and then either exits cleanly
or aborts so the OS can produce a core dump.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reports` | boolean | `true` | Write a crash-report file on panic (message, location, thread, version, backtrace) |
| `backtrace` | boolean | `true` | Capture a full backtrace in the report (independent of `RUST_BACKTRACE`) |
| `report_dir` | string | `~/.local/state/sipnab` | Directory crash reports (`sipnab-crash-<timestamp>-<pid>.log`) land in |
| `core` | boolean | `false` | `true`: abort after the report so the kernel can dump core (subject to `ulimit -c` / `core_pattern`); `false`: exit cleanly with status 101, suppressing the core |

```toml
[crash]
reports = true
backtrace = true
report_dir = "/var/log/sipnab"
core = false
```

### [theme]

TUI color theme with 11 semantic color slots (plus `highlight`, a legacy alias for `selected`). Each field accepts a color name or a hex RGB value. Unset fields use built-in defaults. See [theme-guide.md](theme-guide.md) for the full customization guide and its preset themes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `background` | string | `"reset"` (terminal default) | Terminal background |
| `foreground` | string | `"white"` | Default text color |
| `highlight` | string | -- | Legacy alias for `selected` (backward compat) |
| `header` | string | `"cyan"` | Status bar, column headers, endpoint labels |
| `selected` | string | `"yellow"` | Selected/highlighted row, cursor, focused item |
| `accent` | string | `"magenta"` | Correlation info, PDD, extended flow labels |
| `good` | string | `"green"` | Positive quality, success states (InCall, Registered) |
| `warning` | string | `"yellow"` | Medium quality, caution states (Ringing, CANCEL) |
| `bad` | string | `"red"` | Poor quality, failures, errors |
| `muted` | string | `"dark_gray"` | Separators, pipes, disabled text, timestamps |
| `border` | string | `"white"` | Widget borders, panel frames |
| `status_bg` | string | `"#303040"` | Status bar background band, kept distinct from the terminal background so the status line stays visible |

Supported color values:
- Named: `black`, `white`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `gray`, `dark_gray`, `reset`
- Hex RGB: `"#RRGGBB"` (e.g., `"#ff8800"`)

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

### [keybindings]

TUI key binding overrides. The 11 configurable actions appear below. Unset fields use built-in defaults.

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
| `search` | string | `"/"` | Activate search |
| `settings` | string | `"F8"` | Open settings popup |
| `pause` | string | `"p"` | Pause/resume capture |
| `autoscroll` | string | `"A"` | Toggle autoscroll |
| `extended_flow` | string | `"F4"` | Toggle extended multi-leg flow |
| `clear_calls` | string | `"F5"` | Clear all calls |
| `column_selector` | string | `"F10"` | Open column selector |

See [keybindings.md](keybindings.md) for the full shortcut reference, including the keys that are not remappable.

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

<!-- vale sipnab.Headings = YES -->

## Full example

A configuration for a SIP monitoring server:

```toml
# /etc/sipnab/sipnab.toml
# Production SIP monitoring configuration

# -- Packet capture --
[capture]
device = "eth0"                    # Primary SIP-facing interface
portrange = "5060-5080"            # Cover SIP, SIP-TLS, and alternate ports
snaplen = 65535                    # Full packet capture (no truncation)
buffer = 32                        # 32 MiB kernel buffer for burst tolerance
buffer_budget_mb = 128             # Cap on the in-flight capture->processing queue
no_rtp = false                     # RTP analysis enabled

# -- Display settings --
[display]
color = "always"                   # Force color even when piped
payload_limit = 8192               # Show up to 8K of SIP body (large SDP)
delta_time = true                  # Show timing between messages by default
from_to = "host-port"              # From/To columns show host:port
# visible_columns = ["method", "from", "to", "state", "msgs", "pdd"]  # Persistent column prefs

# -- Default filter (optional) --
[filter]
from = "^1001@"
to = "^1002@"
expression = "method == 'INVITE' OR method == 'REGISTER'"

# -- Security detection --
[security]
kill_scanner = true                # Detect SIP scanners (sipvicious, etc.)
kill_response = 403                # Reply to scanners with 403
fraud_detect = true                # Heuristic fraud detection
alert = ["syslog", "json"]        # Send alerts to syslog and JSON log
alert_exec = "/usr/local/bin/sipnab-alert.sh"  # Custom alert handler
reg_flood_threshold = 10           # REGISTER/sec from one source that is a flood
kill_rate_limit = 10               # Kill responses/sec sipnab may transmit
business_hours = "8-18"            # Enables off-hours fraud detection (UTC hours)

# -- Diagnosis thresholds --
[diagnosis]
post_dial_delay_secs = 8.0         # Toll-call target; the default 11.0 is international
ack_timeout_secs = 32.0            # RFC 3261 Timer H
late_media_ms = 500                # Media allowed to start this late after the 200 OK

# -- Resource limits --
[limits]
dialog_limit = 50000               # Max tracked dialogs (tune for RAM)
max_streams = 25000                # Max RTP streams
max_reassembly = 5000              # Max TCP reassembly sessions
hep_rate_limit = 25000             # Max HEP packets/sec
lint_max_per_rule = 25             # Repeats of one lint finding per dialog

# -- Privilege separation (Linux) --
[privilege]
user = "sipnab"                    # Drop to unprivileged user after device open
no_priv_drop = false               # Keep privilege dropping enabled
chroot = "/var/lib/sipnab"         # Chroot after initialization

# -- Address naming --
[names]
enabled = true                     # Resolve addresses to names at startup
hosts_file = "/etc/sipnab/hosts"   # Preloaded IP -> name mappings

[names.manual]
"192.0.2.1" = "sbc-edge"

# -- Crash handling --
[crash]
reports = true                     # Write a crash report on panic
backtrace = true                   # Include a full backtrace
core = false                       # Exit 101 rather than dumping core

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

> **Tip:** Use `sipnab --dump-config` to see which file sipnab actually loaded
> and what that file set. It prints the path it came from, then every section
> header with the keys that file supplied under each.
>
> Read the omissions carefully, because `-D` shows less than "effective
> configuration" suggests:
>
> - **Built-in defaults do not appear.** A key you did not set prints nothing,
>   not its default. `sipnab -F --dump-config` therefore prints a list of empty
>   section headers, which is correct output and not a fault. The defaults are
>   the ones in the tables on this page.
> - **CLI flags do not appear.** They arrive later in startup, so `-D` cannot
>   show what a flag would override. Compare against the
>   [CLI reference](cli-reference.md) for that.
> - **There is no environment-variable override layer.** `SIPNAB_CONFIG` only
>   selects which file to read.
>
> So `-D` answers "did sipnab read the file I meant, and did it accept my
> keys?" — which is the question behind most configuration surprises. It does
> not answer "what value is this setting running with?".
