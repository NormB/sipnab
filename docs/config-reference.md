# Config reference

sipnab reads configuration from a TOML file. CLI flags ([cli-reference.md](cli-reference.md)) always override config file values.

Configuration is optional.

- With no file present, sipnab runs on its built-in defaults.
- A config file exists to set persistent defaults for your environment.

## Minimal Config

If you only need to override a few defaults, keep it short:

```toml
# ~/.config/sipnab/sipnab.toml
[capture]
device = "eth0"
# Your trunks also use 5080: widen the signaling ports.
portrange = "5060-5080"

[diagnosis]
# Local traffic: report setup slower than 6 seconds.
post_dial_delay_secs = 6.0
```

`sipnab -D` prints the configuration it loaded. So you can check the file took
effect.

## File Locations

sipnab reads configuration from the first file it finds in this order:

| Priority | Source |
|----------|--------|
| 1 | `--config <FILE>` (must exist; errors if missing) |
| 2 | `$SIPNAB_CONFIG` environment variable |
| 3 | `$XDG_CONFIG_HOME/sipnab/sipnab.toml`, or `~/.config/sipnab/sipnab.toml` when `$XDG_CONFIG_HOME` is unset, empty or not an absolute path |
| 4 | `~/.sipnabrc` |
| 5 | `/etc/sipnab/sipnab.toml` |

sipnab reads only that first file.

- It does not merge a later one into it.
- So a setting in `~/.sipnabrc` does nothing while
  `~/.config/sipnab/sipnab.toml` exists.

When more than one of rows 3 to 5 exists, sipnab says which file it read and
which it did not. It says so in three places:

- a warning on stderr;
- a line in `--dump-config` output;
- the status line when the terminal UI opens.

A `--config` file or `$SIPNAB_CONFIG` is your choice, so it raises no such
notice.

```text
# Loaded from: /home/you/.config/sipnab/sipnab.toml
# Also present and NOT read: /home/you/.sipnabrc
```

- Use `--no-config` (`-F`) to skip all file loading.
- Use `--dump-config` (`-D`) to print which file sipnab loaded and the keys it
  set. See the note under [Full example](#full-example) for what `-D` does and
  does not show.

Unknown keys produce a warning and go no further. So one config can span
versions.

## Environment variables in values

Any string value may contain `${NAME}`. sipnab substitutes that environment
variable's value when it reads the file:

```toml
[crash]
report_dir = "/home/${SUDO_USER}/sipnab"
```

The case this exists for is `sudo`.

- Capture needs privileges, so sipnab often runs under `sudo`.
- After `sudo -i`, a file written by that run lands in root's directory. It
  does not land in the directory of whoever ran the command.
- `${SUDO_USER}` is the only thing that can say which one that is at the moment
  sipnab reads the file.

Four rules, and they hold everywhere a string does:

- **`${NAME}` expands.**
  - `NAME` is an ASCII letter or `_` followed by letters, digits or `_`.
  - sipnab rejects shell's `${NAME:-default}` and `${NAME-other}` outright
    rather than half-supporting them.
- **An unset variable is an error.**
  - sipnab names the setting and the variable and does not start.
  - Expanding to nothing would turn `/home/${SUDO_USER}/sipnab` into
    `/home//sipnab`.
  - That is a real, writable directory that is not the one you meant.
- **`$$` is a literal `$`.** Write `$${NAME}` for a literal `${NAME}`.
- **A bare `$NAME` is literal text.** Braces are the whole syntax.

What a variable expands to is data. sipnab never scans it again. So a value
that itself contains `${...}` stays as it is.

`--dump-config` prints values after expansion. That is what sipnab is actually
using.

## Format

Standard [TOML](https://toml.io/). All sections and keys are optional. Only set values you want to change from defaults.

A file sipnab cannot read, or a value in it sipnab refuses, stops the run
before anything starts.

- The exit status is `1`, and the message names the key.
- The same value given as a flag exits `2`.
- See [Exit codes](cli-reference.md#exit-codes).

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
| `device` | string | -- | Default network interface. `--device` overrides it |
| `node_name` | string | hostname | Name this box reports as, in `capture_identity.node` on every MCP and REST answer. Lets an agent querying several servers tell WHICH one saw a given fact. `--node-name` overrides it, so a deployed config can name the box while a one-off command relabels it. The default puts the hostname on the wire. Clipped to 64 characters. sipnab refuses an empty value (exit 1) |
| `portrange` | string | `"5060-5061"` | SIP **signaling** port range; media is never gated by it. sipnab skips any SIP message with both ports outside the range, and a skipped message reaches no count, no dialog and no output — so this key decides how much of a capture you analyze at all. Widen it (`"1-65535"`) unless you know every port in play. `--portrange` overrides it |
| `ws_ports` | string | `"80, 443, 8080, 8443"` | Ports carrying SIP-over-WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118.html)), as one inclusive `"START-END"` range in the same grammar as `portrange`. The shipped set is the browser's view of the web, not a deployment's: Kamailio, OpenSIPS and Janus each default to WSS outside it, and behind a reverse proxy sipnab sees whichever port the proxy forwards to — on such a capture the entire WebRTC signaling leg stays invisible. A range **replaces** the shipped set, exactly as `portrange` replaces the default signaling ports. sipnab counts the SIP-over-WebSocket it declines to unwrap and names the ports it arrived on. `--ws-portrange` overrides it |
| `snaplen` | integer | `65535` | Snapshot length in bytes. sipnab refuses `0`, which keeps no byte of any packet, as `--snaplen` does. `--capture-profile` overrides it; `--snaplen` overrides it |
| `buffer` | integer | `64` | Kernel capture buffer size in MiB (per device). sipnab refuses `0`, which asks the kernel for no ring, as `--buffer` does. `--buffer` overrides it |
| `buffer_budget_mb` | integer | `64` | Memory budget for the in-flight capture→processing queue. Grows under load up to this budget (capped, never OOM) and shrinks when idle. `--buffer-budget` overrides it |
| `no_rtp` | boolean | `false` | Disable RTP capture by default. `--no-rtp` turns it on. `--rtp` forces it off |
| `promisc` | boolean | `true` | Put a named interface into promiscuous mode (the `any` device is never promiscuous). `--no-promisc` overrides this to `false` |
| `hep_parse` | boolean | `false` | Unwrap HEP-encapsulated SIP found in the capture, as `-E` / `--hep-parse` does: each message takes the addresses and the time the HEP packet carries, or the time sipnab captured the wrapper when the HEP packet carries none. For a proxy that mirrors HEP to a loopback port that sipnab sniffs (`device = "lo"`), so that several readers can see the same copies. Keep a receiver bound to that port: with no process bound to it, some senders lose messages, as the note below this table describes. `--no-hep-parse` turns it off for one run. Feature: `hep` |
| `bpf_filter` | string | -- | Capture (BPF) filter, as the trailing positional filter on the command line takes, handed to libpcap as typed. Not the display filter, which is `[filter] expression`. While it holds a filter, sipnab generates none from `portrange`. The trailing positional filter (`<BPF_FILTER>`) or `--bpf-file` replaces it. It applies to capture files too, and a run that reads a file through it says so on stderr |

```toml
[capture]
device = "eth0"
portrange = "5060-5080"
ws_ports = "8080-8090"
snaplen = 65535
buffer = 16
buffer_budget_mb = 64
no_rtp = false
promisc = true
```

The loopback HEP deployment, from the file alone. A proxy mirrors HEP to
UDP/9063 on `lo`, and any number of readers sniff it at once:

```toml
[capture]
device = "lo"
portrange = "1-65535"
ws_ports = "1-65535"
hep_parse = true
bpf_filter = "udp dst port 9063"
```

sipnab reads the copies without any process listening on UDP/9063. But a port
with no listener costs messages with some senders.

- The kernel answers each datagram sent to a closed port with an ICMP
  port-unreachable message.
- A sender that uses a connected UDP socket then fails its next send.
- Measured on 2026-10-07 with sipnab's own sender before it changed:
  - `sipnab -H
    127.0.0.1:19063` sent a 7-message call to a port with no listener;
  - 3 of the 7 sends failed;
  - a reader on `lo` saw 4 messages.
- sipnab's `-H` now sends UDP from an unconnected socket.
  - The kernel does not report the ICMP message to that socket.
  - So it loses no message this way.
  - On 2026-10-08 the same run to a port with no listener reported 7 sent and
    none failed.
- Other senders, such as a proxy's HEP module, still may.
  - Whether a proxy loses copies this way depends on whether its HEP sender
    uses a connected socket.

Keep a receiver bound to the port while you sniff it. `sipnab -L 127.0.0.1:9063`
is one, and it reads the copies itself.

### [display]

Output and TUI display settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `color` | string | `"auto"` | Color mode: `"auto"`, `"always"`, `"never"`. sipnab refuses any other value, naming the key. `--color` overrides it |
| `payload_limit` | integer | -- | Maximum payload bytes to display. `--payload-limit` overrides it |
| `delta_time` | boolean | `false` | Show delta time between messages by default. `--delta-time` turns it on. `--no-delta-time` forces it off |
| `from_to` | string | `"default"` | From/To column display: `"default"` (user else host:port), `"host-port"`, `"user"`, `"user-host-port"`. Cycle at runtime with `u`; `--from-to-mode` overrides this |
| `mouse_capture` | boolean | `true` | Whether the TUI captures the mouse when it starts. `false` opens it with capture off, so the terminal's own drag-to-select works; `F12` toggles capture at runtime. With capture on, the mouse wheel scrolls |
| `view_filter_detail` | string | `"summary"` | How status line 3 shows the filter the F7 dialog built. `"summary"` names each selection in a few words, such as `F7: 7 methods, From~alice`. `"full"` shows the expression. A filter typed as an expression is always shown in full. The `filter_detail` key (default `F`) toggles it at runtime. sipnab refuses any other value, naming the key |
| `visible_columns` | array of strings | all columns | Call-list columns to show, by name (case-insensitive): `"#"`, `"Method"`, `"From"`, `"To"`, `"Source"`, `"Destination"`, `"State"`, `"Msgs"`, `"Date"`, `"PDD"`, `"Duration"`. Adjust at runtime with F10; `s` in the column selector writes the layout into the config file this run loaded (or the user config file (`$XDG_CONFIG_HOME/sipnab/sipnab.toml`, by default `~/.config/sipnab/sipnab.toml`) when none was), so it persists across sessions. sipnab refuses that save when the settings came from `/etc/sipnab/sipnab.toml` |

```toml
[display]
color = "always"
payload_limit = 4096
delta_time = true
from_to = "user-host-port"
view_filter_detail = "full"
visible_columns = ["method", "from", "to", "source", "destination", "state", "msgs", "pdd"]
```

### [filter]

Default filter presets applied at startup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `from` | string | -- | Default From header filter (regex). sipnab refuses a pattern that does not compile when the file loads, naming the key. `--from` overrides it |
| `to` | string | -- | Default To header filter (regex). sipnab refuses a pattern that does not compile when the file loads, naming the key. `--to` overrides it |
| `expression` | string | -- | Default filter DSL expression. `--filter` overrides it |

```toml
[filter]
from = "^1001@"
to = "^1002@"
expression = "method == 'INVITE'"
```

### [filters]

Named filters. Each key is a name and each value a filter expression.

Use a name as `@name` wherever sipnab takes a filter expression:

- `--filter`;
- `--export-vcon-when`;
- `[filter] expression`;
- the REST `filter` parameter;
- an MCP tool's `filter` argument;
- the TUI filter dialog's Named filter field.

See [Named filters](filter-dsl.md#named-filters).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| any name | string | -- | A filter expression, which may reference other names and the built-in aliases as `@name`. A name is 1 to 64 ASCII letters, digits, `-` or `_`, and starts with a letter or digit |

```toml
[filters]
carrier-a = "src.ip in_subnet '203.0.113.0/24'"
support   = "to.user == '7000' OR header.X-Queue == 'support'"
sales     = "@carrier-a AND to.user =~ '^8[0-9]{3}$'"
```

sipnab resolves every name when it starts. It refuses to start, exit code 1,
naming the entry, when:

- a name does not parse or is a built-in alias;
- an entry references a name nothing defines;
- entries reference each other in a loop;
- an expansion is not a valid expression.

### [vcon]

vCon export settings: the export rules and enrichment services, each an
array of tables that you write once per entry, and the sealing keys every
rule inherits when it does not set its own.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rule` | array of tables | `[]` | Export rules, each `[[vcon.rule]]`. See [the export rule keys](#vconrule) |
| `enrich` | array of tables | `[]` | Enrichment services, each `[[vcon.enrich]]`. See [the enrichment keys](#vconenrich) |
| `encrypt_to` | string | -- | The `encrypt_to` of every `[[vcon.rule]]` that sets none: with it, every rule encrypts. A rule's own value overrides it |
| `sign_key` | string | -- | The `sign_key` of every encrypting `[[vcon.rule]]` that sets none. A rule's own value overrides it |
| `sign_cert` | string | -- | The `sign_cert` of every encrypting `[[vcon.rule]]` that sets none. A rule's own value overrides it |
| `compress` | string | `none` | The `compress` of every encrypting `[[vcon.rule]]` that sets none: `none` or `gzip`. A rule's own value overrides it |

### [[vcon.rule]]

Export rules. Each pairs a filter with the directory its vCon containers go to
and what they carry.

- A run can hold several.
- sipnab writes a call matching several once per rule.
- See [Write calls by rule](vcon.md#write-calls-by-rule).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | -- | The rule's name, 1 to 64 ASCII letters, digits, `-` or `_`. Required and unique |
| `when` | string | -- | The filter a call must match; `@name` [named filters](filter-dsl.md#named-filters) resolve. Required |
| `dir` | string | -- | The directory the rule writes to. Required |
| `audio` | string | `omit` | `inline` carries the retained audio inside each container; `url` writes it to a WAV beside the container and names it by URL (see `audio_url_base`); both turn audio retention on for the run. `omit` carries none |
| `audio_url_base` | string | -- | For `audio = "url"`: the HTTPS base URL your storage serves the rule's WAV files from. sipnab writes each WAV beside its container and names `<base>/<file>` in it |
| `max_inline_media_mib` | integer | `--vcon-max-inline-media` | The largest audio this rule's containers inline, in MiB; sipnab writes a call above it without its audio, saying so |
| `live_audio` | boolean | `false` | Serve each matching call's audio while it is in progress on the REST API's `/v1/calls/{call_id}/audio` WebSocket, and list the calls at `/v1/calls/live`. Turns audio retention on. See [Hear a call while it is in progress](vcon.md#hear-a-call-while-it-is-in-progress) |
| `live` | boolean | `false` | On a live capture, write each matching call's container as the call starts and rewrite it in place, with `updated_at`, each time the call changes. No effect with `-I`. See [Follow a call while it is in progress](vcon.md#follow-a-call-while-it-is-in-progress) |
| `encrypt_to` | string | -- | A PEM certificate whose RSA key the rule encrypts its containers to. Set, the rule writes only the encrypted form of draft-ietf-vcon-vcon-core-04 section 5.3. Needs `sign_key` and `sign_cert`. See [Encrypt what a rule writes](vcon.md#encrypt-what-a-rule-writes) |
| `sign_key` | string | -- | The PEM RSA private key an encrypting rule signs with, readable by its owner only |
| `sign_cert` | string | -- | The PEM certificate chain of `sign_key`, leaf first, carried in each signature's `x5c` |
| `compress` | string | `none` | For an encrypting rule: `gzip` signs the gzip ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.html)) of the vCon instead of the vCon, as draft-ietf-vcon-vcon-core-04 section 5.2 allows, and the encrypted form names `cty: "application/vcon+gzip"`; `none` signs the vCon as it is. Refused on a rule without `encrypt_to`. See [Encrypt what a rule writes](vcon.md#encrypt-what-a-rule-writes) |
| `sealed_updates` | string | `new-uuid` | What an encrypting rule writes when a call it already wrote changes. `new-uuid`: a new instance with a new uuid whose `amended` names the prior one (draft-ietf-vcon-vcon-core-04 section 4.1.9). `same-uuid`: rewrite the file under the same uuid, with a startup warning. `final-only`: write once, when the call ends. sipnab refuses any other value at startup. No effect without `encrypt_to`. See [When an encrypted call changes](vcon.md#when-an-encrypted-call-changes) |
| `grouping` | string | `leg` | `leg`: one container per dialog, each naming the call's other legs. `call`: one container per call, holding every leg the rule selects and the ties between them. See [Calls through a PBX or a B2BUA](vcon.md#calls-through-a-pbx-or-a-b2bua) |

```toml
[[vcon.rule]]
name  = "support-with-audio"
when  = "to.user == '7000'"
dir   = "/var/spool/sipnab-vcon/support"
audio = "inline"
```

### [[vcon.enrich]]

Enrichment services.

- sipnab sends each one the calls of the rules it names, before it writes their
  containers.
- It appends the Analysis Objects of its answer.

<!-- The link text repeats the heading it links to, whose wording the anchor
fixes. See the comment above that heading in vcon.md. -->
<!-- vale Google.Passive = NO -->

See [Enrich a call before it is written](vcon.md#enrich-a-call-before-it-is-written).

<!-- vale Google.Passive = YES -->

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | -- | The service's name, recorded in every container sipnab sent it. 1 to 64 ASCII letters, digits, `-` or `_`. Required and unique |
| `rules` | array of strings | -- | The `[[vcon.rule]]` names whose calls go to this service. Required |
| `url` | string | -- | Where sipnab POSTs the request: `https://`, or `http://` to a loopback address only. One of `url` and `command` |
| `command` | string | -- | A program run per call, reading the request on stdin and answering on stdout. One of `url` and `command` |
| `auth_file` | string | -- | A file holding one `Header-Name: value` line sent with each request, such as `Authorization: Bearer ...`. Never written to a container |
| `timeout_secs` | integer | `120` | How long sipnab waits for the answer, 1 to 3600: the default is `DEFAULT_TIMEOUT_SECS` (120) and the largest `MAX_TIMEOUT_SECS` (3600) in [`src/app/vcon_enrich.rs`](https://github.com/NormB/sipnab/blob/main/src/app/vcon_enrich.rs) |
| `send` | array of strings | `["audio", "signaling"]` | What sipnab sends the service: `audio` (each leg's WAV), `signaling` (the container), or both. Sending audio turns audio retention on for the run |

### [pbx]

The PBX sipnab runs beside, for the filter field `side`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `addresses` | array of strings | `[]` | The PBX's own addresses, each an IP address or a CIDR range. `side` is `inbound` for a call whose opening request went to one of them and `outbound` for one sent from one of them. sipnab refuses to start, exit code 1, naming the entry, when an entry is neither |

```toml
[pbx]
addresses = ["192.0.2.10", "198.51.100.0/24"]
```

### [sip]

SIP protocol handling.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `xcid_headers` | array | `[]` | Header names used to correlate B2BUA call legs (`sip.xcid`). A dialog whose message carries one of these headers pointing at another dialog's Call-ID joins that dialog. Add your estate's headers here. Empty by default: sipnab picks no `X-` name for you ([RFC 6648](https://www.rfc-editor.org/rfc/rfc6648.html)), and the identifier that crosses a B2BUA by design is [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989.html) `Session-ID`, which correlates with no configuration. An empty list turns the header strategy off |
| `leg_correlation_window_ms` | integer | `2000` | How far apart, in milliseconds, one call's two legs may start and still correlate on TIMING alone. This is the B2BUA timing heuristic's whole content, and the only strategy left once a B2BUA has rewritten every identifier the other six compare. The shipped two seconds describes a PBX placing the outbound leg immediately, not one doing an LNP or ENUM dip, or walking an LCR cascade, before it places one. Widen it on such a hop; every correlation still reports the strategy that matched, so a guess stays labeled as one. `--leg-correlation-window` overrides it |
| `active_idle_window_secs` | integer | `3600` | Seconds a dialog may go untouched and still count toward the active-dialog and active-call gauges every surface publishes. The shipped hour is twice [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028.html)'s default `Session-Expires`, which grounds it for a trunk carrying session timers and not for a contact center, where a caller parked on hold past an hour is a channel in use the gauge stops counting. Widening it widens the opposite error -- a call that never sent its BYE keeps counting for longer, and that one never recovers on its own -- so raise it for traffic that genuinely goes quiet. `--active-idle-window` overrides it. `0` fails validation and names the key |

```toml
[sip]
xcid_headers = ["X-Call-ID", "X-CID"]
leg_correlation_window_ms = 8000
active_idle_window_secs = 7200
```

### [security]

Security detection defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kill_scanner` | boolean | `false` | Enable scanner detection. `--kill-scanner` turns it on. `--no-kill-scanner` forces it off |
| `kill_response` | integer | `200` | SIP response code for scanner reports (100-699). `--kill-response` overrides it |
| `fraud_detect` | boolean | `false` | Enable fraud detection heuristics. `--fraud-detect` turns it on. `--no-fraud-detect` forces it off |
| `alert` | array of strings | `[]` | Alert channels: `"syslog"`, `"json"`, `"exec"`. `--alert` overrides it; `--alert-json` also turns it on; `--syslog` also turns it on |
| `alert_exec` | string | -- | Command to execute on alert. `--alert-exec` overrides it |
| `reg_flood_threshold` | integer | `50` | Challenged failures from one source inside one `reg_flood_window_secs` window before `--reg-flood` reports a flood: REGISTERs that carried credentials and drew a `401` or `407` on the same transaction. The default is a carrier-registrar figure: it never sees the ten-a-second brute force a small PBX gets. Counted in capture time, so a file replays as the traffic it recorded. `--reg-flood-threshold` overrides it. `0` fails validation and names the key |
| `reg_flood_window_secs` | integer | `1` | How much capture time one registration-flood counting window spans, in seconds. `reg_flood_threshold` counts failures per window, so this decides how concentrated a credential-guessing run has to be: one refusal every two seconds never puts two inside the default one-second window. Range 1-3600. sipnab refuses `0`, which would reset the count on every packet, and anything past an hour, where the count is a daily tally rather than a rate, and names the key. `--reg-flood-window` overrides it |
| `reg_flood_transaction_timeout_ms` | integer | `32000` | How long a credentialed REGISTER stays open to the `401`/`407` that answers it, in milliseconds. The default is [RFC 3261 Timer F](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.2.2), 64 times T1 at the [default T1 of 500 ms](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.1). sipnab never counts a challenge that arrives later as a failure. Set it to 64 times your network's T1, or to your registrar-side proxy's final-response timer when that is longer (see [Registration-flood timers](troubleshooting.md#registration-flood-timers)). Range 1000-600000. Below one second every challenge arrives after its transaction ends and the detector counts nothing, so sipnab refuses the value and names the key. `--reg-flood-transaction-timeout` overrides it |
| `kill_rate_limit` | integer | `10` | Scanner-kill responses per second sipnab may put on the wire. This bounds the one feature that answers an address out of the capture, and whoever forged the source address chose where each response goes, so there is no unlimited setting and `0` fails validation. A per-destination cap of 3 per minute applies underneath, so raising this widens how many distinct hosts sipnab answers, never how hard it hits one. `--kill-rate-limit` overrides it |
| `business_hours` | string | -- | Business hours as `"START-END"` in whole UTC hours, for example `"8-18"`. A wrapping range such as `"22-6"` is the overnight window. This is what makes the off-hours fraud detection reachable: with no window declared there is no outside for a call to fall in. `--business-hours` overrides it |
| `fraud_short_call_secs` | integer | `3` | Measured call duration below which `--fraud-detect` counts a completed call as short for wangiri detection. Three seconds is under a normal ring-no-answer on some carriers, which reports ordinary unanswered calls as lures. `--fraud-short-call` overrides it |
| `fraud_wangiri_calls` | integer | `3` | Short calls to one destination prefix before `--fraud-detect` reports wangiri. `--fraud-wangiri-calls` overrides it |
| `fraud_destination` | string | -- | Destination countries `--fraud-detect` reports an INVITE to, as comma-separated ISO 3166-1 alpha-2 codes (`DO,VG,MA`). sipnab reads numbers through the common international prefixes (`+`, `00`, `011`) and resolves them by longest calling code, so `+1 809` is `DO`, not `US`; a number with no prefix is domestic and never matches. `--fraud-destination` overrides it |
| `fraud_sequential_calls` | integer | `3` | Consecutive refused numbers before `--fraud-detect` reports sequential scanning. `--fraud-sequential-calls` overrides it |
| `fraud_volume_multiplier` | integer | `5` | Multiple of a source's own baseline call rate that `--fraud-detect` reports as a volume spike. `--fraud-volume-multiplier` overrides it |
| `fraud_volume_min_calls` | integer | `6` | Calls a source must place inside the volume window before `--fraud-detect` reports a spike at all. `--fraud-volume-min-calls` overrides it |
| `fraud_volume_window_secs` | integer | `60` | How much capture time one volume-spike window spans, in seconds. The count and the source's own baseline are both measured over this window, so a steady source reads the same at any width; what the width alone decides is how CONCENTRATED a burst has to be, since a burst shorter than the window averages into the ordinary traffic beside it. `--fraud-volume-window` overrides it |
| `fraud_wangiri_window_secs` | integer | `60` | How much capture time one wangiri window spans, in seconds. The detector drops short calls older than this, so it decides how slowly a lure may arrive and still count as one pattern. No setting of `fraud_wangiri_calls` reaches a lure paced wider than the window: the only count that reports anything is one, which reports every ordinary short call as a lure too. `--fraud-wangiri-window` overrides it |
| `scanner_behavioral_probes` | integer | `10` | Probes from one source inside the scanner window, above which `--kill-scanner` reports a rate detection. Behind an SBC every source collapses to one address, so ordinary aggregated traffic clears ten in five seconds and the whole site reads as one scanner. `--scanner-behavioral-probes` overrides it |
| `scanner_enumeration_targets` | integer | `5` | Distinct target extensions from one source inside the scanner window, above which `--kill-scanner` reports extension enumeration. `--scanner-enumeration-targets` overrides it |
| `scanner_rejected_probes` | integer | `5` | Rejected probes inside the scanner window at which a source reads as probing rather than operating. This is the evidence gate: neither behavioral signal reports anything until a source clears this or `scanner_unanswered_probes`, which is what separates an enumeration sweep from a trunk running keepalives at the same rate. `--scanner-rejected-probes` overrides it |
| `scanner_unanswered_probes` | integer | `5` | Probes inside the scanner window that drew no response, at which a source reads as sweeping, provided they also outnumber the rest of what it sent. `--scanner-unanswered-probes` overrides it |
| `scanner_window_secs` | integer | `5` | How much capture time one scanner window spans, in seconds. Every scanner count above is per window, so this is the binding constraint on a paced sweep rather than the counts: one probe every ten seconds never puts two inside the shipped five-second window, so the rate and the spread both stay at one however low the counts go. `--scanner-window` overrides it |
| `scanner_established_factor` | integer | `4` | How much more evidence `--kill-scanner` needs from a source that has completed a registration or a call. A registered endpoint that starts probing is a compromised phone worth reporting, but it is also the peer whose ordinary working traffic looks most like probing, and the peer a false positive costs most. `--scanner-established-factor` overrides it |
| `scanner_answer_grace_ms` | integer | `500` | How long a probe may go without a response before `--kill-scanner` counts it as unanswered, in milliseconds. The default is [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html)'s Timer T1, the round-trip estimate at which SIP itself gives up waiting and retransmits. Raise it on a link whose round trip runs longer than that, where the default reports every probe still in flight as one nobody answered. `--scanner-answer-grace` overrides it |
| `findings_history` | integer | `1000` | Security findings kept in memory for later retrieval. `0` keeps none, which is a real setting rather than a mistake. `--findings-history` overrides it |
| `hep_hmac_window_secs` | integer | `30` | Seconds either side of now within which sipnab still honors a `--hep-auth-mode hmac` token's timestamp. On an agent/collector pair with poor NTP sipnab turns every packet away as out-of-window, and what the operator sees is a collector receiving NOTHING -- a symptom they attribute to routing, a firewall, or a dead agent long before a clock. Widening it is a security trade rather than a convenience: the window is exactly how long a packet an on-path attacker captured stays acceptable, and it is how far back the receiver's nonce cache must remember. Range 1-300. Past 300 the sender has no working time daemon, which is what to repair, so sipnab refuses the value and names the key. On a run without `--hep-listen` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-hmac-window` overrides it |

**HEP HMAC token version 2, and what a mixed fleet sees.** sipnab 0.5.131
moved `HMAC_TOKEN_VERSION` from 1 to 2 and refuses v1 by name. Two things
follow.

- A sender still on 0.5.130 or earlier against a newer collector has **every
  packet refused**.
  - The symptom is a collector receiving nothing.
  - Operators reliably attribute that to routing, a firewall, or a dead agent
    long before they suspect a token version.
  - Upgrade the collector last, or upgrade both together.
- The second thing is the reason it is not a compatible change.
  - v1's MAC did not cover the addressing chunks.
  - So an attacker who captured a v1 token from one sender could replay it
    against a third party.
  - The attacker could also point a published `--hep-allow-kill` control
    somewhere nobody issued it for.
  - v2 covers them.
  - There is no flag to accept v1 again, deliberately.

sipnab bounds `reg_flood_window_secs` and `reg_flood_transaction_timeout_ms`
at both ends.

- A value outside the range fails validation. The message holds the key, the
  range and the value.
- The `--reg-flood-window` and `--reg-flood-transaction-timeout` flags refuse
  the same values.
- That is because both doors read the same constants in [`src/security/reg_flood.rs`](https://github.com/NormB/sipnab/blob/main/src/security/reg_flood.rs):
  - `MAX_WINDOW_SECS` (3,600);
  - `MIN_TRANSACTION_TIMEOUT_MS` (1,000);
  - `MAX_TRANSACTION_TIMEOUT_MS` (600,000).

Every `scanner_*` key above rejects `0` and names the key.

- A zero count reports the first probe of any kind as a scanner.
- A zero window resets the counters on every packet, so nothing ever
  accumulates.
- A zero grace restores the very defect `scanner_answer_grace_ms` exists to
  prevent.

```toml
[security]
kill_scanner = true
kill_response = 403
kill_rate_limit = 10
fraud_detect = true
business_hours = "8-18"
fraud_short_call_secs = 2
fraud_wangiri_window_secs = 900
reg_flood_threshold = 10
reg_flood_window_secs = 10
reg_flood_transaction_timeout_ms = 64000
scanner_window_secs = 60
scanner_behavioral_probes = 40
scanner_enumeration_targets = 12
findings_history = 5000
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/sipnab-alert.sh"
```

### `[tfps]`

> **The peer this needs.** These read [TFPS](https://github.com/sippulse/tfps)
> through its `tfps_ctl` program in JSON mode, the `--json` flag.
>
> - TFPS gained that mode in [sippulse/tfps#6](https://github.com/sippulse/tfps/pull/6),
>   merged on 2026-09-18.
> - No tagged release carries it yet. v0.2.1, the newest, rejects `--json`.
>
> Until the next release, build TFPS from its `master` branch.
>
> - To check the `tfps_ctl` you have, run `tfps_ctl status --json`.
>   - One line of JSON means it is ready.
>   - `unknown option: --json` means it predates the mode.
> - Against an older `tfps_ctl`, these answer with that error and name what to
>   install.
>
> The kernel-drop question (`GET /v1/tfps/dropped`, the `tfps_dropped` MCP
> tool) is the exception. It needs a `dropped` subcommand that no TFPS build
> has, released or on `master`.

Where the toll-fraud prevention system (TFPS) is, when one runs on this host.

TFPS is optional peer software. It condemns sources and enforces that
decision in the firewall.

- sipnab bans nothing on its own.
- It asks TFPS to ban only when you turn that on under [`[actions]`](#actions).
- The `tfps_*` MCP tools and the `/v1/tfps/` REST routes ask it through its
  `tfps_ctl` program.
- This section says where that program and its database are.
- Leave the section out, and sipnab:
  - looks for `tfps_ctl` on `PATH` the moment a TFPS tool runs;
  - does nothing about TFPS at any other time.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ctl` | string | -- | Path to `tfps_ctl`. `--tfps-ctl` overrides it. Absent: sipnab looks on `PATH` the moment a TFPS tool runs. On a machine with no `tfps_ctl` anywhere, every read answers `installed: false`, and sipnab refuses a ban that actions allow, as one it could not ask TFPS about (`502` over REST). An empty string fails validation and names the key |
| `db` | string | -- | The TFPS database, passed to every `tfps_ctl` call as `--db <path>`: two arguments, which a wrapper script standing in for `tfps_ctl` receives as `"$@"`. Absent: `tfps_ctl` uses its own default. An empty string fails validation and names the key |

```toml
[tfps]
ctl = "/usr/local/bin/tfps_ctl"
db = "/var/lib/tfps/tfps.db"
```

### `[actions]`

What sipnab may change in another system, and from where. **Empty by
default: sipnab changes no system outside itself.**

- It publishes what it saw to destinations you name.
- It asks other software read-only questions.
- An action, such as asking TFPS to ban a source, runs only when enabled here
  or with `--allow-action`. The two add together.

One key per target. Each is a list of the surfaces that may ask:

- `"rest"` for the REST API;
- `"mcp"` for the MCP tools.

A target or surface sipnab does not know stops it at startup. sipnab does not
read it as "nothing enabled".

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tfps` | list of strings | `[]` | Surfaces that may ask TFPS to ban and unban, and back a ban out: `POST /v1/tfps/ban`, `/unban` and `/v1/actions/revert` over REST; `tfps_ban`, `tfps_unban` and `actions_revert` over MCP. A REST caller also needs a token minted with `--token-scope actions`, and so does an MCP client over HTTP. `--allow-action` adds to it |

Enabling anything needs the [actions journal](#journal). sipnab refuses to
start without a directory it can use for it.

```toml
[actions]
tfps = ["rest"]
```

### `[action_limits]`

The limits every action passes. They exist for two reasons:

- so a stolen credential or a runaway agent can do only so much;
- so that every ban ends on its own.

Rules for the keys:

- Each key left out keeps the value shown.
- None can be `0`. That would turn the limit off, so sipnab refuses to start
  instead.
- The limits survive a restart. sipnab rebuilds them from the journal, so
  crashing it does not reset them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `per_minute` | integer | `10` | Actions per minute from everyone together |
| `per_caller_per_minute` | integer | `5` | Actions per minute from one caller: one token, or one MCP stdio client. Cannot be above `per_minute` |
| `address_cooldown_secs` | integer | `60` | Seconds an address rests after an action on it before the next, so no one can flip a ban on and off |
| `default_ban_secs` | integer | `3600` | How long a ban lasts when the caller does not say |
| `max_ban_secs` | integer | `604800` | The longest ban sipnab asks for (7 days). sipnab refuses a longer request, or `0` (TFPS's "forever"), rather than shortening it |

Whatever these say, sipnab never bans some addresses:

- `0.0.0.0`;
- the broadcast address;
- loopback and multicast addresses.

```toml
[action_limits]
per_minute = 20
per_caller_per_minute = 5
address_cooldown_secs = 60
default_ban_secs = 1800
max_ban_secs = 86400
```

### `[journal]`

Where sipnab records the actions it takes. After a restart or a crash, it
then knows:

- which bans are its own;
- what was in flight;
- how much of each limit it has spent.

`sipnab --journal-show` prints what it holds. `sipnab --revert-actions` backs
actions out.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dir` | string | `/var/lib/sipnab/journal` | The journal directory. `--journal-dir` overrides it. sipnab creates it with mode 0700 if absent, and the packaged service gets `/var/lib/sipnab` from systemd. Each record reaches the disk before the action it describes runs, and the files hold no token or request body. Files close at 16 MiB, and sipnab deletes closed files more than 90 days old when the next one starts. An empty string fails validation and names the key |

```toml
[journal]
dir = "/srv/sipnab/journal"
```

### [diagnosis]

Thresholds the signaling and media checks compare against.

- A number here decides whether a call that is working gets reported as
  broken.
- So the defaults are standards figures.
- A network that knows its own numbers beats a recommendation written for the
  general case.

Every value must be a finite number greater than zero.

- sipnab refuses `0`, a negative number, `nan` and `inf`, naming the key.
- `duration_asymmetry_pct` must also be 100 or less.
- `cn_suppression_ratio` must be 1 or less.
- `late_media_ms` is a whole number of at least 1.
- The matching flags follow the same rules.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `post_dial_delay_secs` | float | `11.0` | Post-dial delay over which sipnab reports a call as slow, in seconds. The default is the ITU-T E.721 Table 2 target that 95 percent of international connections must meet, because a capture does not say which kind of call it holds. Tighten it to 8.0 for toll or 6.0 for local traffic. `--pdd-threshold` overrides it |
| `ack_timeout_secs` | float | `32.0` | Seconds a `2xx` may go unacknowledged before the missing `ACK` counts as a fault rather than as a capture that stopped early. The default is [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) Timer H. `--ack-timeout` overrides it |
| `no_final_response_secs` | float | `180.0` | Seconds an `INVITE` may sit without a final response before the silence gets reported. The default is RFC 3261 Timer C. Below it, every call still ringing when the capture stopped gets reported. `--no-final-response-timeout` overrides it |
| `duration_asymmetry_pct` | float | `5.0` | Percentage difference between the two legs' durations that counts as asymmetric. Must be 100 or less. `--duration-asymmetry-pct` overrides it |
| `duration_asymmetry_secs` | float | `2.0` | Absolute difference between the two legs' durations that counts as asymmetric, in seconds. A call has to clear both this and the percentage, so raising either one alone quiets the detection. `--duration-asymmetry-secs` overrides it |
| `late_media_ms` | integer | `500` | Milliseconds after the `200 OK` that media may start before it gets reported as late. `--late-media-ms` overrides it |
| `cn_suppression_ratio` | float | `0.3` | Share of a call's packets, as a fraction of 1, that must be comfort noise before sipnab accepts comfort noise as the explanation for one-directional media. **The one threshold here that withholds a finding instead of raising one**, so it fails as silence: a VoLTE or mobile trunk running aggressive voice-activity detection routinely passes 30 percent comfort noise, and above the ratio sipnab never reports one-way audio on that trunk — the most-reported VoIP fault there is. Raise it toward 1 on such a trunk; lower it where a call carrying any comfort noise at all still has to be bidirectional. Must be greater than 0 and 1 or less, and a value that is not fails validation and names the key. `--cn-suppression-ratio` overrides it |

```toml
[diagnosis]
post_dial_delay_secs = 6.0
ack_timeout_secs = 32.0
no_final_response_secs = 180.0
duration_asymmetry_pct = 5.0
duration_asymmetry_secs = 2.0
late_media_ms = 500
cn_suppression_ratio = 0.3
```

## `[media]`

Properties of the observed media path that a passive tap cannot measure for
itself.

| Key | Type | Default | Description |
|---|---|---|---|
| `one_way_delay_ms` | float | -- | One-way network path delay in milliseconds, feeding the delay term of every MOS. The single MOS input no observer can measure from the wire directly: only the endpoints and you have it. A declared value beats an RTCP-reported round trip, because no packet can rewrite a config file; that beats the round trip sipnab derives from a sender-report echo carried in a receiver report, which anchors on the capture point and so reads as a lower bound; with none of the three, sipnab assumes 100 ms and labels the figure `assumed` rather than presenting it as measured. `--one-way-delay` overrides it |
| `codec_ie` | table | -- | Equipment impairment factors (ITU-T G.107 `Ie`) for codecs sipnab has no published value for, written as a `[media.codec_ie]` sub-table of `"CODEC" = <Ie>` pairs. sipnab knows G.711, G.729 and Opus; every other codec -- G.722, G.726, iLBC, AMR, EVS -- falls to a placeholder and scores identically to a stream whose codec was never identified. A declared codec comes back as `mos_grounding = "operator_declared"` rather than as published, so a figure from this file is never presented as an ITU-T citation, and a codec nobody declared still says its MOS is a placeholder. Keys match case-insensitively. Values must sit in `0.0` to just under `95.0`: at 95 the E-model's loss term vanishes, and above it more packet loss would RAISE the score, so sipnab fails validation on such a value and names the codec |
| `listening_context` | string | `"monotic"` | How the far end listens, for wideband (AMR-WB) MOS: `"monotic"` (a handset or one-ear headset, ITU-T G.113 Table IV.1) or `"diotic"` (a stereo headset or speakerphone, Table IV.3). At 6.6 kbit/s the two differ by about 0.59 MOS, and a capture cannot tell which one was in use, so you declare it. Every wideband score names the context sipnab read it in. Case and surrounding spaces do not matter; any other value stops the run with an error naming the key |

```toml
[media]
one_way_delay_ms = 45.0
listening_context = "diotic"   # the far end uses a stereo headset or speakerphone

# Impairment factors for codecs sipnab has no published value for.
[media.codec_ie]
G722 = 12.0
iLBC = 11.0
```

### [quality]

Where the quality color column turns yellow, and where it turns red.

- A number here decides only what catches an operator's eye during triage.
- That is a different question from `[diagnosis]`. That one decides whether a
  call that is working counts as broken.

The defaults suit a general-purpose trunk. The right values belong to the
network you are watching.

- 30 ms of jitter is already a fault on a LAN PBX.
- 1 percent loss is unremarkable on an international one.

Rules for the values:

- Unset keys keep the shipped default. So a file may move one boundary without
  restating the other seven.
- Every value must be a finite number of zero or more.
- Each warn boundary must leave a reachable middle against its matching bad
  boundary. A set that does not fails validation and names the key.
- Zero itself counts as a real setting. `loss_warn_pct = 0.0` means any loss at
  all is worth a color.

These bands paint the TUI.

- A `-N` run prints the measurements themselves rather than a color.
- So sipnab validates a band set on a non-interactive run and then never
  consults it.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jitter_warn_ms` | float | `30.0` | Jitter at or above which the column turns yellow, in milliseconds. `--jitter-warn-ms` overrides it |
| `jitter_bad_ms` | float | `50.0` | Jitter at or above which the column turns red, in milliseconds. `--jitter-bad-ms` overrides it |
| `loss_warn_pct` | float | `1.0` | Loss at or above which the column turns yellow, in percent. `--loss-warn-pct` overrides it |
| `loss_bad_pct` | float | `5.0` | Loss at or above which the column turns red, in percent. `--loss-bad-pct` overrides it |
| `mos_warn` | float | `4.0` | MOS below which the column turns yellow. MOS bands run downward, so this must sit at or above `mos_bad`. `--mos-warn` overrides it |
| `mos_bad` | float | `3.0` | MOS below which the column turns red. `--mos-bad` overrides it |
| `rtt_warn_ms` | float | `300.0` | Round trip at or above which the column turns yellow, in milliseconds. The default is ITU-T G.114's 150 ms one-way guidance doubled. `--rtt-warn-ms` overrides it |
| `rtt_bad_ms` | float | `800.0` | Round trip at or above which the column turns red, in milliseconds. The default is G.114's 400 ms one-way figure doubled. `--rtt-bad-ms` overrides it |

```toml
[quality]
jitter_warn_ms = 10.0
jitter_bad_ms = 20.0
loss_warn_pct = 0.5
loss_bad_pct = 2.0
mos_warn = 4.2
mos_bad = 3.5
rtt_warn_ms = 120.0
rtt_bad_ms = 300.0
```

### [limits]

Resource limits to prevent unbounded memory growth.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dialog_limit` | integer | `100000` | Maximum tracked dialogs. `--limit` overrides it |
| `mcp_max_rows` | integer | `1000` | Maximum rows in ONE list-style MCP response. Distinct from `dialog_limit` above, which bounds the whole run; these differ by 100x and bound different things. `0` fails validation and names the key. `--mcp-max-rows` overrides it |
| `max_streams` | integer | `50000` | Maximum RTP streams. `0` fails validation and names the key. `--max-streams` overrides it |
| `max_reassembly` | integer | `10000` | Maximum TCP reassembly sessions. `0` fails validation and names the key. `--max-reassembly` overrides it |
| `reassembly_ttl_secs` | integer | `30` | Seconds sipnab holds an incomplete IP datagram or half-read TCP stream before a sweep drops it. `max_reassembly` bounds how MANY entries sipnab holds and says nothing about how long. Thirty seconds describes IP fragments in flight, and the TCP reassembler inherited it: a persistent SIP/TCP or SIP/TLS trunk to a carrier goes quiet for far longer on any ordinary night, and sweeping its half-read stream means the next segment re-initializes mid-message, so the peer that sent a valid message is the one reported broken. Raise it on such a trunk; `max_reassembly` caps the extra state either way. `--reassembly-ttl` overrides it. `0` fails validation and names the key |
| `hep_rate_limit` | integer | `50000` | Maximum HEP packets per second. On a run without `--hep-listen` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-rate-limit` overrides it |
| `max_header_line` | integer | `8192` | Maximum bytes in a single SIP header (defense-in-depth) |
| `max_headers_per_message` | integer | `200` | Maximum SIP headers per message (defense-in-depth) |
| `max_messages_per_dialog` | integer | `500` | Maximum stored messages per dialog (defense-in-depth) |
| `idle_compact_after_secs` | integer | `600` | Seconds of silence before sipnab compacts a dialog's stored messages. `0` fails validation and names the key |
| `keep_messages_per_idle_dialog` | integer | `20` | Messages an idle dialog keeps after compaction |
| `max_audio_frames` | integer | unset | Maximum RTP payload frames retained per stream for WAV and vCon export. Unset keeps the whole call. When set, the oldest frame goes first, and the export says PARTIAL and counts the frames dropped. At 20 ms packetization, 1500 frames is 30 seconds. `0` fails validation and names the key |
| `max_audio_bytes` | integer | `1073741824` | Bytes of retained RTP payload across every stream, the bound on audio retention. See [Audio retention budget](#audio-retention-budget). Below `1048576` (1 MiB) fails validation and names the key |
| `lint_max_per_rule` | integer | `25` | Findings one lint rule may report for one dialog. A dialog that retransmits an `INVITE` eleven times trips a message rule eleven times and every one of them is true, so this decides whether the other rules stay readable underneath. `--lint-max-per-rule` overrides it. `0` fails validation and names the key |
| `exec_queue_depth` | integer | `100` | Hook commands allowed to be running at once before sipnab drops `--on-dialog-exec` and `--on-quality-exec` events. The second ceiling above `--exec-rate-limit`, and the binding one for any hook that takes longer than a second: its slot is still occupied when the next second's budget arrives, so on a busy trunk this is what events actually meet. `--exec-queue-depth` overrides it. `0` fails validation and names the key |
| `mcp_max_body_bytes` | integer | `4096` | Bytes of SIP body or matched snippet in ONE MCP response. `mcp_max_rows` bounds how many rows an answer carries; this bounds how wide one row may be, and a caller can ask for fewer rows but cannot widen one. `--mcp-max-body-bytes` overrides it. `0` fails validation and names the key |
| `mcp_max_response_bytes` | integer | `1048576` | Bytes of ONE whole paged MCP response: the JSON page, the provenance note and the completeness fields. `mcp_max_rows` bounds how many rows a page carries and `mcp_max_body_bytes` how wide one body in a row can be; this bounds the page as a whole. Past it the tool drops whole rows from the end of the page, never part of one, and answers `truncated: true`, `truncated_by: "bytes"` and a `next_cursor` to the rest. A page always keeps at least one row, so following the cursor always moves forward. A caller narrows it per call with `max_response_bytes` and cannot exceed it. The default, 1 MiB, is under twice the largest response measured on the sample captures in `tests/pcap-samples` (561,420 bytes, `list_dialogs` with `limit: 1000`), so it changes no answer on those. `--mcp-max-response-bytes` overrides it. `0` fails validation and names the key |
| `mcp_max_wait_seconds` | integer | `60` | Longest ONE `await_condition` MCP call may wait, in seconds. `mcp_max_rows` and `mcp_max_body_bytes` bound what an answer carries; this bounds how long a caller may hold one of `--mcp-max-concurrent` slots while carrying nothing. sipnab clamps a larger request to it and says so in the response. It also bounds `wait_seconds` on `find_in_captures` and `find_in_captures_status`. `--mcp-max-wait-seconds` overrides it. `0` fails validation and names the key |
| `mcp_max_findings` | integer | `1000` | Findings the MCP `save_findings` tool accepts before refusing further writes. The one WRITE budget on that surface: `mcp_max_rows` and `mcp_max_body_bytes` bound what an agent may READ, this bounds what it puts into the operator's journal. Past it sipnab refuses the write and says so, and drops nothing to make room -- a finding is a log line the journal already holds, so sipnab keeps no copy a newer one could displace. Raise it for a long agent session on a large capture, where a thousand annotations is a session doing its job. `--mcp-max-findings` overrides it. `0` fails validation and names the key |
| `mcp_sweep_max_files` | integer | `20` | Files one MCP `find_in_captures` sweep may open. It is the ceiling on the tool's per-call `max_files`: sipnab clamps a larger request to it, and `0` or no request means this value. A rotated spool of forty files needs `40` here before one sweep can reach the oldest file. The response reports the limits applied and `files_examined`, `files_total` and `complete`, so a sweep that stopped early says so. `--mcp-sweep-max-files` overrides it. `0` and values above `4294967295` (the largest per-call `max_files`, a 32-bit unsigned integer) fail validation and name the key |
| `mcp_sweep_deadline_ms` | integer | `30000` | Milliseconds one MCP `find_in_captures` sweep may spend. It is the ceiling on the tool's per-call `deadline_ms`, applied the same way as `mcp_sweep_max_files`. The sweep runs as a background job and checks it before each file and before each packet. `--mcp-sweep-deadline-ms` overrides it. `0` and values above `43200000` (twelve hours, the longest one background sweep may run) fail validation and name the key |
| `mcp_sweep_max_running` | integer | `4` | MCP `find_in_captures` sweeps one server runs at once. Each running sweep is an operating system thread reading capture files. sipnab refuses a start past this many with a message that reports the bound and names this key and `--mcp-sweep-max-running`, rather than queueing it. `--mcp-sweep-max-running` overrides it. `0` and values above `64` (each sweep holds a thread and its own scratch stores) fail validation and name the key |
| `mcp_sweep_max_held_results` | integer | `16` | Finished MCP `find_in_captures` results one server holds for collection. Past this many, sipnab drops the result of the earliest-started sweep first, and refuses a poll of its job id. `--mcp-sweep-max-held-results` overrides it. `0` and values above `256` (four held results per running sweep at the running maximum of 64) fail validation and name the key |
| `mcp_sweep_result_retention_secs` | integer | `600` | Seconds a finished MCP `find_in_captures` result waits for its poll, counted from the moment the sweep finished. After it, the job id is unknown, and sipnab refuses a poll of it with a message that reports this value. `--mcp-sweep-result-retention-secs` overrides it. `0` and values above `43200` (twelve hours, the longest one sweep may run) fail validation and name the key |
| `max_lost_sequences` | integer | `1000` | Lost RTP sequence numbers retained per stream. This is the window the Packet Loss Map draws and the burst/gap analysis reasons over, so a 30-minute call losing 1 % shows only its last minute at the default. The burst/gap window widens with it. `--max-lost-sequences` overrides it. `0` fails validation and names the key |
| `quality_interval_secs` | integer | `5` | Seconds between RTP quality snapshots, which is the resolution of the per-stream quality trend on `rtp_stats`, `GET /v1/streams/{id}`, the TUI and the browser analyzer. The shipped five seconds averages away any burst shorter than itself. The trend still covers an hour of call time whatever this is, so a one-second setting retains 3600 snapshots per stream rather than 720 — resolution costs memory, never history. `--quality-interval` overrides it. Anything outside 1-300 fails validation and names the key |
| `max_groups` | integer | `100000` | Distinct `--group-by` keys one run retains, the same figure `dialog_limit` ships so a grouped run cannot outgrow an ordinary capture. Past it sipnab refuses new keys and warns that the output is incomplete. `--max-groups` overrides it |
| `max_grouped_messages` | integer | `200000` | Messages `--group-by` buffers across every group. Grouping cannot stream — the last packet may belong to the first group — so this is memory held until the capture ends. `--max-grouped-messages` overrides it |
| `max_metadata_file_bytes` | integer | `2147483648` | Bytes of pcapng sipnab reads into memory for embedded names and TLS secrets. **A memory-exhaustion guard on untrusted input.** Raising it to N lets ONE file claim N bytes of this host's RAM — roughly 2N while `--strip-secrets` writes its copy — on nothing but a file size, before sipnab can tell the file is a capture at all. Raise it for captures you produced; leave it for captures someone sent you. `--max-metadata-file-bytes` overrides it |
| `max_gunzip_bytes` | integer | `1073741824` | Bytes a gzip-compressed capture may inflate to where sipnab does the inflating: the embedded names and TLS secrets read out of a `.pcapng.gz`, the copy `--strip-secrets` rewrites, and the whole capture in the browser build. libpcap inflates the packet stream of a `-I capture.pcap.gz` run and this does not bound it. **A gzip-bomb guard.** Inflation stops one byte past the ceiling, so raising it to N lets a few kilobytes claim N bytes of RAM. Raise it for archives you compressed yourself. `--max-gunzip-bytes` overrides it |
| `max_tcp_buffer` | integer | `65536` | Bytes one SIP/TCP direction may buffer before sipnab flushes it. **The only limit here that destroys data rather than truncating a report.** TCP sets no such ceiling and neither does RFC 3261: on a carrier trunk a message carrying ISUP encapsulation, a long `Record-Route` set or a fat SDP offer passes 64 KiB legitimately, and sipnab then flushes the buffer mid-message so both halves parse as malformed — the peer that sent a valid message is the one reported broken. Raise it on such a trunk. The floor is one SIP header line (8192); below that no message survives, and sipnab refuses the value by name. `--max-tcp-buffer` overrides it |
| `api_max_rows` | integer | `1000` | Rows one list-style REST response returns. The REST counterpart of `mcp_max_rows`, settable for the same reason: the right ceiling belongs to the consumer, not to sipnab. A batch consumer piping `/v1/dialogs` to a file wants every row; a dashboard drawing a table wants far fewer. `--api-max-rows` overrides it. `0` fails validation and names the key |
| `api_rate_limit_per_peer` | integer | `100` | REST requests one client IP may make per second. The limiter counts by source address, so a dashboard polling `/v1/streams` on a short timer, or several collectors behind one NAT, share a single allowance and see `503` (`503` rather than `429` because the limiter runs before authentication, so the refusal says nothing about the credential). `0` disables the cap, the reading `hep_rate_limit` and `mcp_rate_limit_per_peer` also give it. At most 4294967295; a larger value fails validation and names the key. `--api-rate-limit-per-peer` overrides it |
| `metrics_max_conn` | integer | `16` | Metrics scrapes served at once before further ones get `503`. The gate stops a burst of slow clients exhausting threads and taking monitoring down, and sixteen suits one Prometheus; an HA pair, a federating parent, a `remote_write` shard, an alertmanager sidecar and one engineer's `curl` reach it without anything unusual happening. A refused scrape leaves a hole in the series that reads as a capture that died rather than as a busy endpoint, so raise it where several collectors share one sipnab. `--metrics-max-conn` overrides it. `0` fails validation and names the key: the gate would then refuse every scrape |
| `max_tracked_peers` | integer | `4096` | Distinct peers one rate-limit window holds, across every surface sipnab meters: HEP source addresses and MCP callers. Past it sipnab REFUSES a peer it has not already seen this second rather than waving it through, so on a collector aggregating from more agents than this the surplus never enters the capture. Raise it there. The floor is 2, and sipnab refuses a smaller value by name: at 1 the first peer to send in a window takes the only slot and sipnab turns every other peer away for the rest of it |
| `max_capture_sources` | integer | `65536` | Distinct capture sources sipnab remembers by name: each input file, the device, every HEP sender (`capture_id@address`) and every traced process. The table holds a name so a packet can point back at the bytes it came from: the `frame` field of `--json`, which `--show-frame` follows and `--mcp-evidence-ring` keys on. Past the limit a packet from a NEW source is still analyzed, but carries no `frame` pointer, and sipnab counts it in `sipnab_capture_sources_refused_total` and warns once. sipnab refuses to start when the limit cannot hold every source the run can have: the input files, or the device, plus `max_tracked_peers` senders on a HEP listener. Raise it, or lower `max_tracked_peers`. The floor is 1. Flag: `--max-capture-sources` |

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
max_audio_bytes = 1073741824
```

How the limits behave when they fill:

- The compaction pair is `idle_compact_after_secs` and
  `keep_messages_per_idle_dialog`.
  - This is where a limit discards a ladder sipnab already holds.
  - So a call that went quiet shows fewer messages than crossed the wire.
  - sipnab warns once per run when this first happens.
- The retention logs (`max_audio_frames` when set, `max_audio_bytes`,
  `max_lost_sequences`) drop their oldest entries as they fill.
- Every other key here refuses to take something in.

Raise both when the ladder matters more than the footprint. These all go quiet
for longer than ten minutes while still being the thing under investigation:

- a call parked on hold;
- a dialog waiting on a slow PSTN leg;
- a capture you paused.

For example:

```toml
[limits]
idle_compact_after_secs = 3600
keep_messages_per_idle_dialog = 500
```

#### Audio retention budget

The terminal UI, and any run with `--retain-audio`, keeps each RTP stream's
G.711, G.722 and Opus payload. Then sipnab can write it to a WAV file or a vCon.

- By default sipnab keeps the whole call, from the first frame.
- `max_audio_bytes` bounds the memory this uses, across every stream at once.

sipnab charges each retained frame against the budget:

- the payload, plus a quarter of its length, plus 32 bytes: an upper bound on
  what the memory allocator spends on it;
- 32 bytes for each slot of the stream's frame buffer, spare capacity
  included.

For 20 ms G.711 (160 bytes a frame) that is 264 bytes a frame:

- 13,200 bytes a second for each direction;
- 26,400 bytes a second for a call with media both ways.

The default of 1 GiB (1,073,741,824 bytes) therefore holds 40,672
call-seconds, which is:

| Calls held at once | Each lasting |
|---|---|
| 1 | 11.3 hours |
| 67 | 10 minutes |
| 225 | 3 minutes |

The charge is an upper bound.

- Measured on aarch64 Linux with the allocator the sipnab binary ships with
  (mimalloc), a 20 ms G.711 frame used 192.6 bytes.
- So at the budget, the heap the audio really holds is about 0.73 GiB.
- With `--cores N`, each worker gets 1/N of the budget. So the run as a whole
  stays inside it.

When retained audio reaches the budget, sipnab releases frames:

- It releases the earliest frames of the oldest stream that still holds audio.
- It releases one frame at a time, until the total is back inside it.
- On a live capture the oldest stream is normally a call that has already
  ended.

sipnab counts the frames released on the stream.

- That call's WAV export, its vCon `media_note`, and the note inside the WAV
  then say `PARTIAL: the [limits] max_audio_bytes retention budget was reached and
  released N earlier frame(s)`.
- Its vCon wraps the recording in a `recording-set` that carries the call's own
  start and duration.
- sipnab never drops audio without counting it.

A live capture that writes vCon containers (`--export-vcon-when` or
`--export-vcon` with a device) releases each call's audio once it writes the
call's container. The container carries it. An export of that call made later
says how many frames sipnab released and why.

Raise `max_audio_bytes` for a host that keeps more or longer calls in memory at
once.

- In the source, the default is `DEFAULT_MAX_AUDIO_BYTES` (1073741824).
- The minimum is `MIN_MAX_AUDIO_BYTES` (1048576).
- Set `max_audio_frames` to cap each stream as well. For example, 1500 frames
  is the last 30 seconds of a 20 ms stream.

### [mcp]

Which tools the MCP server registers, and whether it sends their output
schemas.

- Every tool sipnab offers a client costs its context window before the agent
  asks anything.
- So give a client that needs a few tools only those few.
- See [Choosing which tools load](mcp-tools.md#choosing-which-tools-load) for
  what each bundle holds.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tools` | list of strings | `["full"]` | Bundles (`core`, `signaling`, `captures`, `security`, `media`, `relay`, `tfps`, `server`, `vcon`, `tls`), single tool names, names from `[mcp.bundles]`, or `full`. sipnab refuses to start, naming the entry, when a name is unknown or empty. Names are case-sensitive. `--mcp-tools` replaces the list |
| `output_schemas` | boolean | `false` | Send each tool's output schema on `tools/list`. MCP makes them optional, and they are more than half of what the tools cost a client. Responses carry the same JSON either way. `--mcp-output-schemas` overrides it |
| `bundles` | table | -- | `[mcp.bundles]`: your own bundles, each a name for a list of tool names and built-in bundles. A custom bundle cannot reuse a built-in bundle or tool name, cannot be empty, and cannot hold `full` or another custom bundle; sipnab refuses to start, naming the bundle, when one breaks a rule, even when nothing uses it |
| `tls_cert` | string | -- | PEM certificate chain MCP over HTTP serves HTTPS with, the server's certificate first. Needs `tls_key`. Used only with `--mcp --mcp-transport http`. See [MCP TLS](mcp-deploy.md#mcp-tls). An empty string fails validation and names the key. `--mcp-tls-cert` overrides it |
| `tls_key` | string | -- | PEM private key for `tls_cert`. sipnab refuses a key any other user on the host can read. An empty string fails validation and names the key. `--mcp-tls-key` overrides it |

```toml
[mcp]
tools = ["core", "voice"]

[mcp.bundles]
voice = ["media", "get_sdp_timeline", "check_codec_negotiation"]
```

### [api]

Which `Host` names the REST API answers, beyond `localhost`, `127.0.0.1`,
`::1` and the address `--api` binds (any IP address on a `0.0.0.0` or `::`
bind).

- The check stops a web page from reaching the API through your browser by
  pointing its own name at `127.0.0.1` (DNS rebinding).
- See [Which `Host` names the API answers](rest-api.md#which-host-names-the-api-answers).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allowed_hosts` | list of strings | `[]` | Extra `Host` values to serve, such as a reverse proxy's public name. `name:port` accepts that port only. `"*"` turns the check off. `--api-allowed-host` replaces the list |
| `tls_cert` | string | -- | PEM certificate chain the REST API serves HTTPS with, the server's certificate first. Needs `tls_key`. Used only when `--api` starts the API. See [API TLS](rest-api.md#api-tls). An empty string fails validation and names the key. `--api-tls-cert` overrides it |
| `tls_key` | string | -- | PEM private key for `tls_cert`. sipnab refuses a key any other user on the host can read. An empty string fails validation and names the key. `--api-tls-key` overrides it |

```toml
[api]
allowed_hosts = ["sipnab.example.com"]
tls_cert = "/etc/sipnab/api.pem"
tls_key = "/etc/sipnab/api.key"
```

### TLS files in the config file

`[api]`, `[mcp]` and `[metrics]` each take a `tls_cert` and `tls_key`.
`[hep]` takes the HEP sender's and listener's TLS files.

- The listener itself still starts on the command line (`--api`,
  `--mcp --mcp-transport http`, `--metrics`, `--hep-send`, `--hep-listen`).
- The keys say what it serves with when it starts.

How the flags and keys combine:

- Each flag replaces its own key. A certificate from the command line and its
  key from the file make a pair.
- Once sipnab combines the flags and the file, a certificate without a key, or
  a key without a certificate, stops it at startup.
  - The message names the half you set.
  - It also names both the flag and the key that would set the other.
  - This check covers every listener's keys, whether or not this run starts it.
- Each of these stops sipnab at startup when the listener starts, naming the
  file:
  - a file sipnab cannot read;
  - a file with no certificate or no private key;
  - a key any other user can read;
  - a key that is not the certificate's.

### [metrics]

How the metrics endpoint serves when `--metrics` starts it.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls_cert` | string | -- | PEM certificate chain the metrics endpoint serves HTTPS with, the server's certificate first. Needs `tls_key`. See [Metrics TLS](prometheus-metrics.md#metrics-tls). An empty string fails validation and names the key. `--metrics-tls-cert` overrides it |
| `tls_key` | string | -- | PEM private key for `tls_cert`. sipnab refuses a key any other user on the host can read. An empty string fails validation and names the key. `--metrics-tls-key` overrides it |

```toml
[metrics]
tls_cert = "/etc/sipnab/metrics.pem"
tls_key = "/etc/sipnab/metrics.key"
```

### [hep]

TLS for HEP:

- the CA the sender (`--hep-send-transport tls`) checks the collector's
  certificate against;
- the certificate a TLS listener (`--hep-listen-transport tls`) presents.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls_ca` | path | -- | CA (PEM) the sender checks the collector's certificate against. It **replaces** the host's CA bundle: the sender accepts only certificates this file issued. Set this or `tls_extra_ca`, not both. An empty string fails validation and names the key. On a run without `--hep-send` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-tls-ca` overrides it |
| `tls_extra_ca` | path | -- | CA (PEM) the sender trusts **in addition to** the host's CA bundle. Set this or `tls_ca`, not both. The host must have a CA bundle; without one sipnab refuses at startup. An empty string fails validation and names the key. On a run without `--hep-send` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-tls-extra-ca` overrides it |
| `tls_cert` | path | -- | PEM certificate chain a TLS HEP listener presents, the server's certificate first. A TLS listener needs this and `tls_key`, from here or from the flags. An empty string fails validation and names the key. On a run without `--hep-listen` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-tls-cert` overrides it |
| `tls_key` | path | -- | PEM private key for `tls_cert`. sipnab refuses a key any other user on the host can read. An empty string fails validation and names the key. On a run without `--hep-listen` it does nothing, and sipnab says so in a startup warning naming the key. `--hep-tls-key` overrides it |

The sender's trust is one setting.

- When the command line names `--hep-tls-ca` or `--hep-tls-extra-ca`, it
  replaces both `tls_ca` and `tls_extra_ca`.
- So a `tls_ca` in the file cannot combine with an `--hep-tls-extra-ca` on the
  command line.

```toml
[hep]
tls_extra_ca = "/etc/sipnab/collector-ca.pem"
```

### `[vcon_forward]`

The vCon forwarder's settings (`sipnab --vcon-forward <SPOOL_DIR>`, see
[Deliver the spool to a store](vcon.md#deliver-the-spool-to-a-store)).

- The spool and `--vcon-forward-once` stay on the command line.
- The credential's value has no key.
  - `auth_file` names the file that holds it.
  - `--vcon-forward-auth` or the `SIPNAB_VCON_FORWARD_AUTH` environment
    variable carries it without a file.
- A flag replaces its key.
- With neither, a `kind` other than `generic` supplies the value. Then the
  default applies.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kind` | string | `"generic"` | The kind of store: `generic`, `vcon-store` or `conserver`. A kind supplies the ingest path when `url` names no path and the header when the credential is a bare key; no kind changes the container sent. `generic` supplies nothing. `--vcon-forward-kind` overrides it |
| `url` | string | -- | Where the forwarder POSTs each container, `http://` or `https://`. With a `kind` other than `generic` and no path, the store's base URL. Checked when the forwarder starts, by the rule `--vcon-forward-url` follows: sipnab refuses a URL with a user name or password in it, and the message shows that part as `[redacted]`. A URL refused from this key exits `1`, as every refused config value does; the same URL from `--vcon-forward-url` exits `2`. `--vcon-forward-url` overrides it |
| `replace_url` | string | -- | URL template the forwarder PUTs a container to when the POST answers `409`, with `{uuid}` replaced by the container's `uuid`. Checked when the forwarder starts. A template refused from this key exits `1`; from `--vcon-forward-replace-url`, `2`. `--vcon-forward-replace-url` overrides it |
| `auth_file` | path | -- | File holding the credential: one `Header-Name: value` line, or the bare key with a `kind` other than `generic`. Refused when other users can read it, and beside `--vcon-forward-auth` or `SIPNAB_VCON_FORWARD_AUTH`. A file sipnab cannot read, or one that holds no credential, stops the forwarder with exit 1, as any refused key does. `--vcon-forward-auth-file` overrides it |
| `ca` | path | host bundle | The only CA (PEM) trusted for an `https://` store. `--vcon-forward-ca` overrides it |
| `extra_ca` | path | -- | A CA (PEM) trusted for an `https://` store in addition to the host's CA bundle. Refused beside `ca`. `--vcon-forward-ca` and `--vcon-forward-extra-ca` each replace both keys |
| `done` | path | `<SPOOL_DIR>/delivered` | Where a delivered container goes. Must be on the spool's file system. `--vcon-forward-done` overrides it |
| `failed` | path | `<SPOOL_DIR>/failed` | Where a refused container goes, beside `<name>.error.json`. Must be on the spool's file system. `--vcon-forward-failed` overrides it |
| `interval` | integer | `5` | Seconds between passes over the spool, 1 to 3600. `--vcon-forward-interval` overrides it |
| `timeout` | integer | `30` | Seconds to wait to connect, and for each read and write, 1 to 600. `--vcon-forward-timeout` overrides it |
| `backoff_first` | integer | `2` | Seconds a container waits after its first failed try, 1 to 4294967295; each failed try doubles the wait. No longer than `backoff_cap`. `--vcon-forward-backoff-first` overrides it |
| `backoff_cap` | integer | `300` | The longest wait between tries, in seconds, 1 to 4294967295. `--vcon-forward-backoff-cap` overrides it |
| `max_response_head` | integer | `65536` | The most bytes of a store's status line and headers read, 1 to 4294967295. The forwarder treats an answer with more as no answer and retries the container. `--vcon-forward-max-response-head` overrides it |
| `max_error_body` | integer | `8192` | The most bytes of a refusal's body a `<name>.error.json` record keeps, 1 to 4294967295. `--vcon-forward-max-error-body` overrides it |

```toml
[vcon_forward]
kind = "vcon-store"
url = "https://api.vcon.store"
auth_file = "/etc/sipnab/vcon-store.key"
done = "/var/spool/sipnab-vcon-sent"
failed = "/var/spool/sipnab-vcon-held"
interval = 10
```

### `[vcon_fetch]`

The vCon fetcher's settings (`sipnab --vcon-fetch <UUID>...`, see
[Fetch a stored vCon](vcon.md#fetch-a-stored-vcon)).

- The uuids, `--vcon-fetch-out` and `--vcon-fetch-overwrite` stay on the
  command line.
- The credential's value has no key. `auth_file` names the file that holds it.
- A flag replaces its key.
- With neither, a `kind` other than `generic` supplies the value. Then the
  default applies.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `kind` | string | `"generic"` | The kind of store: `generic`, `vcon-store`, `conserver` or `vcon-mcp`. A kind supplies the read path after the path the URL names, the header when the credential is a bare key, and the removal of what the store wraps around the container. `generic` supplies nothing. `--vcon-fetch-kind` overrides it |
| `url` | string | -- | The store's base URL, or, for the `generic` kind, a URL template holding `{uuid}`. Checked when the fetcher starts, by the rule `--vcon-fetch-url` follows. A URL refused from this key exits `1`; the same URL from `--vcon-fetch-url` exits `2`. `--vcon-fetch-url` overrides it |
| `auth_file` | path | -- | File holding the credential: one `Header-Name: value` line, or the bare key with a `kind` other than `generic`. Refused when other users can read it. A file sipnab cannot read, or one that holds no credential, stops the fetcher with exit 1, as any refused key does. `--vcon-fetch-auth-file` overrides it |
| `ca` | path | host bundle | The only CA (PEM) trusted for an `https://` store. `--vcon-fetch-ca` overrides it |
| `extra_ca` | path | -- | A CA (PEM) trusted for an `https://` store in addition to the host's CA bundle. Refused beside `ca`. `--vcon-fetch-ca` and `--vcon-fetch-extra-ca` each replace both keys |
| `decrypt_key` | path | -- | The RSA private key (PEM, readable by its owner only) that decrypts an encrypted container. `--vcon-fetch-decrypt-key` overrides it |
| `signer_ca` | path | -- | The CA (PEM) a decrypted container's signing certificate must chain to, through the intermediates in its `x5c`, every certificate within its validity period; `system` for the host's CA bundle. Needs `decrypt_key`. `--vcon-fetch-signer-ca` overrides it |
| `signer_sha256` | string | -- | The SHA-256 fingerprint the signing certificate of a decrypted container must have: 64 hex digits, plain or colon-separated, either case. Needs `decrypt_key`. `--vcon-fetch-signer-sha256` overrides it |
| `timeout` | integer | `30` | Seconds to wait to connect, and for each read and write, 1 to 600. `--vcon-fetch-timeout` overrides it |
| `max_size` | integer | `67108864` | The largest answer read for one container, in bytes, 1 to 4294967295. `--vcon-fetch-max-size` overrides it |
| `max_response_head` | integer | `65536` | The most bytes of a store's status line and headers read, 1 to 4294967295. `--vcon-fetch-max-response-head` overrides it |

```toml
[vcon_fetch]
kind = "vcon-store"
url = "https://api.vcon.store"
auth_file = "/etc/sipnab/vcon-store.key"
timeout = 60
```

### [privilege]

Privilege separation settings (Linux only).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user` | string | `"nobody"` | User to drop privileges to after opening capture devices. `--user` overrides it |
| `no_priv_drop` | boolean | `false` | Disable privilege dropping. `--no-priv-drop` turns it on. `--priv-drop` forces it off |
| `chroot` | string | -- | Chroot directory after initialization. `--chroot` overrides it |

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
| `enabled` | boolean | `false` | Start with name resolution on (offline sources). `--resolve` turns it on. `--no-resolve` forces it off |
| `reverse_dns` | boolean | `false` | Also use reverse DNS (PTR) lookups. `--reverse-dns` turns it on. `--no-reverse-dns` forces it off |
| `hosts_file` | string | -- | `/etc/hosts`-format file of IP → name mappings to preload. `--names` adds to it |
| `persist_to_config` | boolean | `false` | When set, in-TUI `N` edits are also written into the `[names.manual]` table below, in the file this run loaded, preserving the rest of it. With no file loaded they go to the user config file (`$XDG_CONFIG_HOME/sipnab/sipnab.toml`, by default `~/.config/sipnab/sipnab.toml`); when the settings came from `/etc/sipnab/sipnab.toml` they are not written and the status line says so when the session opens |
| `dns_cache_entries` | integer | `4096` | Reverse-DNS results (positive and negative) held at once (default `MAX_DNS_CACHE_ENTRIES`). Past the cap sipnab drops the oldest entry, so a capture touching more hosts than this -- a carrier edge, a peering point, or any long `--reverse-dns` window -- keeps re-looking-up addresses it already resolved. Nothing reports that: a dropped lookup only shows as an address displayed unresolved, so the symptom is names that flicker. The worker queue's depth follows this figure; sipnab derives it rather than taking a second number. `--dns-cache-entries` overrides it |
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

What happens when sipnab panics. The panic hook:

- restores the terminal (release builds abort without unwinding, so raw mode /
  mouse capture would otherwise stay on);
- writes a crash report;
- then either exits cleanly or aborts so the OS can produce a core dump.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reports` | boolean | `true` | Write a crash-report file on panic (message, location, thread, version, backtrace) |
| `backtrace` | boolean | `true` | Capture a full backtrace in the report (independent of `RUST_BACKTRACE`) |
| `report_dir` | string | `~/.local/state/sipnab` | Directory crash reports (`sipnab-crash-<timestamp>-<pid>.log`) land in. An empty string fails validation and names the key |
| `core` | boolean | `false` | `true`: abort after the report so the kernel can dump core (subject to `ulimit -c` / `core_pattern`); `false`: exit cleanly with status 101, suppressing the core |

```toml
[crash]
reports = true
backtrace = true
report_dir = "/var/log/sipnab"
core = false
```

### [theme]

TUI color theme with 11 semantic color slots (plus `highlight`, a legacy alias for `selected`).

- Each field accepts a color name or a hex RGB value.
- Unset fields use built-in defaults.
- See [theme-guide.md](theme-guide.md) for the full customization guide and its
  preset themes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `background` | string | `"reset"` (terminal default) | Terminal background |
| `foreground` | string | `"reset"` | Default text color (`reset` is the terminal's own) |
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

TUI key binding overrides. The 12 configurable actions appear below. Unset fields use built-in defaults.

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
| `filter_detail` | string | `"F"` | Show the filter the F7 dialog built as a summary or in full on status line 3. Works in every view, ahead of the view's own keys; sipnab warns at startup when it takes a key a view uses |

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
filter_detail = "F"
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
reg_flood_threshold = 10           # Refused credentialed REGISTERs per window that is a flood
reg_flood_window_secs = 1          # The counting window, in seconds of capture time
reg_flood_transaction_timeout_ms = 32000  # RFC 3261 Timer F: 64 x T1 (500 ms)
kill_rate_limit = 10               # Kill responses/sec sipnab may transmit
business_hours = "8-18"            # Enables off-hours fraud detection (UTC hours)
scanner_window_secs = 60           # Wide enough to hold a sweep paced at one probe/10s
scanner_behavioral_probes = 40     # Raised: this site aggregates behind one SBC address
fraud_wangiri_window_secs = 900    # A lure paced over fifteen minutes is still one lure

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
exec_queue_depth = 20              # Hook commands allowed to run at once

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
> and what that file set.
>
> - It prints the path it came from.
> - It then prints every section header with the keys that file supplied under
>   each.
>
> Read the omissions carefully, because `-D` shows less than "effective
> configuration" suggests:
>
> - **Built-in defaults do not appear.**
>   - A key you did not set prints nothing, not its default.
>   - `sipnab -F --dump-config` therefore prints a list of empty section
>     headers. That is correct output and not a fault.
>   - The defaults are the ones in the tables on this page.
> - **CLI flags do not appear.**
>   - They arrive later in startup, so `-D` cannot show what a flag would
>     override.
>   - Compare against the [CLI reference](cli-reference.md) for that.
> - **There is no environment-variable override layer.** `SIPNAB_CONFIG` only
>   selects which file to read.
>
> So `-D` answers "did sipnab read the file I meant, and did it accept my
> keys?". That is the question behind most configuration surprises. It does not
> answer "what value is this setting running with?".
