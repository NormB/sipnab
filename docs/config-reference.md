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
| `portrange` | string | `"5060-5061"` | SIP **signaling** port range; media is never gated by it. sipnab skips any SIP message with both ports outside the range, and a skipped message reaches no count, no dialog and no output — so this key decides how much of a capture you analyze at all. Widen it (`"1-65535"`) unless you know every port in play. `--portrange` overrides it |
| `ws_ports` | string | `"80, 443, 8080, 8443"` | Ports carrying SIP-over-WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118)), as one inclusive `"START-END"` range in the same grammar as `portrange`. The shipped set is the browser's view of the web, not a deployment's: Kamailio, OpenSIPS and Janus each default to WSS outside it, and behind a reverse proxy sipnab sees whichever port the proxy forwards to — on such a capture the entire WebRTC signaling leg stays invisible. A range **replaces** the shipped set, exactly as `portrange` replaces the default signaling ports. sipnab counts the SIP-over-WebSocket it declines to unwrap and names the ports it arrived on. `--ws-portrange` overrides it |
| `snaplen` | integer | `65535` | Snapshot length in bytes |
| `buffer` | integer | `64` | Kernel capture buffer size in MiB (per device) |
| `buffer_budget_mb` | integer | `64` | Memory budget for the in-flight capture→processing queue. Grows under load up to this budget (capped, never OOM) and shrinks when idle. `--buffer-budget` overrides it |
| `no_rtp` | boolean | `false` | Disable RTP capture by default |
| `promisc` | boolean | `true` | Put a named interface into promiscuous mode (the `any` device is never promiscuous). `--no-promisc` overrides this to `false` |

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
| `leg_correlation_window_ms` | integer | `2000` | How far apart, in milliseconds, one call's two legs may start and still correlate on TIMING alone. This is the B2BUA timing heuristic's whole content, and the only strategy left once a B2BUA has rewritten every identifier the other six compare. The shipped two seconds describes a PBX placing the outbound leg immediately, not one doing an LNP or ENUM dip, or walking an LCR cascade, before it places one. Widen it on such a hop; every correlation still reports the strategy that matched, so a guess stays labeled as one. `--leg-correlation-window` overrides it |

| `active_idle_window_secs` | integer | `3600` | Seconds a dialog may go untouched and still count toward the active-dialog and active-call gauges every surface publishes. The shipped hour is twice [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028)'s default `Session-Expires`, which grounds it for a trunk carrying session timers and not for a contact center, where a caller parked on hold past an hour is a channel in use the gauge stops counting. Widening it widens the opposite error -- a call that never sent its BYE keeps counting for longer, and that one never recovers on its own -- so raise it for traffic that genuinely goes quiet. `--active-idle-window` overrides it. `0` fails validation and names the key |

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
| `kill_scanner` | boolean | `false` | Enable scanner detection |
| `kill_response` | integer | `200` | SIP response code for scanner reports (100-699) |
| `fraud_detect` | boolean | `false` | Enable fraud detection heuristics |
| `alert` | array of strings | `[]` | Alert channels: `"syslog"`, `"json"`, `"exec"` |
| `alert_exec` | string | -- | Command to execute on alert |
| `reg_flood_threshold` | integer | `50` | REGISTER requests per second from one source before `--reg-flood` reports a flood. The default is a carrier-registrar figure: it never sees the ten-a-second brute force a small PBX gets, and it fires all through a re-REGISTER storm on a registrar that just restarted. `--reg-flood-threshold` overrides it. `0` fails validation and names the key |
| `kill_rate_limit` | integer | `10` | Scanner-kill responses per second sipnab may put on the wire. This bounds the one feature that answers an address out of the capture, and whoever forged the source address chose where each response goes, so there is no unlimited setting and `0` fails validation. A per-destination cap of 3 per minute applies underneath, so raising this widens how many distinct hosts sipnab answers, never how hard it hits one. `--kill-rate-limit` overrides it |
| `business_hours` | string | -- | Business hours as `"START-END"` in whole UTC hours, for example `"8-18"`. A wrapping range such as `"22-6"` is the overnight window. This is what makes the off-hours fraud detection reachable: with no window declared there is no outside for a call to fall in. `--business-hours` overrides it |
| `fraud_short_call_secs` | integer | `3` | Measured call duration below which `--fraud-detect` counts a completed call as short for wangiri detection. Three seconds is under a normal ring-no-answer on some carriers, which reports ordinary unanswered calls as lures. `--fraud-short-call` overrides it |
| `fraud_wangiri_calls` | integer | `3` | Short calls to one destination prefix before `--fraud-detect` reports wangiri. `--fraud-wangiri-calls` overrides it |
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
| `scanner_answer_grace_ms` | integer | `500` | How long a probe may go without a response before `--kill-scanner` counts it as unanswered, in milliseconds. The default is [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)'s Timer T1, the round-trip estimate at which SIP itself gives up waiting and retransmits. Raise it on a link whose round trip runs longer than that, where the default reports every probe still in flight as one nobody answered. `--scanner-answer-grace` overrides it |
| `findings_history` | integer | `1000` | Security findings kept in memory for later retrieval. `0` keeps none, which is a real setting rather than a mistake. `--findings-history` overrides it |
| `hep_hmac_window_secs` | integer | `30` | Seconds either side of now within which sipnab still honors a `--hep-auth-mode hmac` token's timestamp. On an agent/collector pair with poor NTP sipnab turns every packet away as out-of-window, and what the operator sees is a collector receiving NOTHING -- a symptom they attribute to routing, a firewall, or a dead agent long before a clock. Widening it is a security trade rather than a convenience: the window is exactly how long a packet an on-path attacker captured stays acceptable, and it is how far back the receiver's nonce cache must remember. Range 1-300. Past 300 the sender has no working time daemon, which is what to repair, so sipnab refuses the value and names the key. `--hep-hmac-window` overrides it |

Every `scanner_*` key above rejects `0` and names the key. A zero count reports
the first probe of any kind as a scanner, a zero window resets the counters on
every packet so nothing ever accumulates, and a zero grace restores the very
defect `scanner_answer_grace_ms` exists to prevent.

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
scanner_window_secs = 60
scanner_behavioral_probes = 40
scanner_enumeration_targets = 12
findings_history = 5000
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/sipnab-alert.sh"
```

### [diagnosis]

Thresholds the signaling and media checks compare against. A number here
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
| `one_way_delay_ms` | float | -- | One-way network path delay in milliseconds, feeding the delay term of every MOS. The single MOS input no observer can measure from the wire directly: only the endpoints and you have it. A declared value beats an RTCP-reported round trip, because no packet can rewrite a config file; that beats the round trip sipnab derives from a sender-report echo carried in a receiver report, which anchors on the capture point and so reads as a lower bound; with none of the three, sipnab assumes 100 ms and labels the figure `assumed` rather than presenting it as measured |
| `codec_ie` | table | -- | Equipment impairment factors (ITU-T G.107 `Ie`) for codecs sipnab has no published value for, written as a `[media.codec_ie]` sub-table of `"CODEC" = <Ie>` pairs. sipnab knows G.711, G.729 and Opus; every other codec -- G.722, G.726, iLBC, AMR, EVS -- falls to a placeholder and scores identically to a stream whose codec was never identified. A declared codec comes back as `mos_grounding = "operator_declared"` rather than as published, so a figure from this file is never presented as an ITU-T citation, and a codec nobody declared still says its MOS is a placeholder. Keys match case-insensitively. Values must sit in `0.0` to just under `95.0`: at 95 the E-model's loss term vanishes, and above it more packet loss would RAISE the score, so sipnab fails validation on such a value and names the codec |

```toml
[media]
one_way_delay_ms = 45.0

# Impairment factors for codecs sipnab has no published value for.
[media.codec_ie]
G722 = 12.0
iLBC = 11.0
```

### [quality]

Where the quality color column turns yellow, and where it turns red. A number
here decides only what catches an operator's eye during triage, which is a
different question from `[diagnosis]`: that one decides whether a call that is
working counts as broken. The defaults suit a general-purpose trunk, and the
right values belong to the network you are watching -- 30 ms of jitter is
already a fault on a LAN PBX, and 1 percent loss is unremarkable on an
international one.

Unset keys keep the shipped default, so a file may move one boundary without
restating the other seven. Every value must be a finite number of zero or more,
and each warn boundary must leave a reachable middle against its matching bad
boundary. A set that does not fails validation and names the key. Zero itself
counts as a real setting: `loss_warn_pct = 0.0` means any loss at all is worth
a color.

These bands paint the TUI. A `-N` run prints the measurements themselves rather
than a color, so sipnab validates a band set on a non-interactive run and then
never consults it.

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
| `dialog_limit` | integer | `100000` | Maximum tracked dialogs |
| `mcp_max_rows` | integer | `1000` | Maximum rows in ONE list-style MCP response. Distinct from `dialog_limit` above, which bounds the whole run; these differ by 100x and bound different things. `0` fails validation and names the key |
| `max_streams` | integer | `50000` | Maximum RTP streams |
| `max_reassembly` | integer | `10000` | Maximum TCP reassembly sessions |
| `reassembly_ttl_secs` | integer | `30` | Seconds sipnab holds an incomplete IP datagram or half-read TCP stream before a sweep drops it. `max_reassembly` bounds how MANY entries sipnab holds and says nothing about how long. Thirty seconds describes IP fragments in flight, and the TCP reassembler inherited it: a persistent SIP/TCP or SIP/TLS trunk to a carrier goes quiet for far longer on any ordinary night, and sweeping its half-read stream means the next segment re-initializes mid-message, so the peer that sent a valid message is the one reported broken. Raise it on such a trunk; `max_reassembly` caps the extra state either way. `--reassembly-ttl` overrides it. `0` fails validation and names the key |
| `hep_rate_limit` | integer | `50000` | Maximum HEP packets per second |
| `max_header_line` | integer | `8192` | Maximum bytes in a single SIP header (defense-in-depth) |
| `max_headers_per_message` | integer | `200` | Maximum SIP headers per message (defense-in-depth) |
| `max_messages_per_dialog` | integer | `500` | Maximum stored messages per dialog (defense-in-depth) |
| `idle_compact_after_secs` | integer | `600` | Seconds of silence before sipnab compacts a dialog's stored messages. `0` fails validation and names the key |
| `keep_messages_per_idle_dialog` | integer | `20` | Messages an idle dialog keeps after compaction |
| `max_audio_frames` | integer | `1500` | Maximum RTP payload frames stored per stream for WAV export (~30s at G.711 50pps) |
| `lint_max_per_rule` | integer | `25` | Findings one lint rule may report for one dialog. A dialog that retransmits an `INVITE` eleven times trips a message rule eleven times and every one of them is true, so this decides whether the other rules stay readable underneath. `--lint-max-per-rule` overrides it. `0` fails validation and names the key |
| `exec_queue_depth` | integer | `100` | Hook commands allowed to be running at once before sipnab drops `--on-dialog-exec` and `--on-quality-exec` events. The second ceiling above `--exec-rate-limit`, and the binding one for any hook that takes longer than a second: its slot is still occupied when the next second's budget arrives, so on a busy trunk this is what events actually meet. `--exec-queue-depth` overrides it. `0` fails validation and names the key |
| `mcp_max_body_bytes` | integer | `4096` | Bytes of SIP body or matched snippet in ONE MCP response. `mcp_max_rows` bounds how many rows an answer carries; this bounds how wide one row may be, and a caller can ask for fewer rows but cannot widen one. `--mcp-max-body-bytes` overrides it. `0` fails validation and names the key |
| `mcp_max_findings` | integer | `1000` | Findings the MCP `save_findings` tool accepts before refusing further writes. The one WRITE budget on that surface: `mcp_max_rows` and `mcp_max_body_bytes` bound what an agent may READ, this bounds what it puts into the operator's journal. Past it sipnab refuses the write and says so, and drops nothing to make room -- a finding is a log line the journal already holds, so sipnab keeps no copy a newer one could displace. Raise it for a long agent session on a large capture, where a thousand annotations is a session doing its job. `--mcp-max-findings` overrides it. `0` fails validation and names the key |
| `max_lost_sequences` | integer | `1000` | Lost RTP sequence numbers retained per stream. This is the window the Packet Loss Map draws and the burst/gap analysis reasons over, so a 30-minute call losing 1 % shows only its last minute at the default. The burst/gap window widens with it. `--max-lost-sequences` overrides it. `0` fails validation and names the key |
| `max_groups` | integer | `100000` | Distinct `--group-by` keys one run retains, the same figure `dialog_limit` ships so a grouped run cannot outgrow an ordinary capture. Past it sipnab refuses new keys and warns that the output is incomplete. `--max-groups` overrides it |
| `max_grouped_messages` | integer | `200000` | Messages `--group-by` buffers across every group. Grouping cannot stream — the last packet may belong to the first group — so this is memory held until the capture ends. `--max-grouped-messages` overrides it |
| `max_metadata_file_bytes` | integer | `2147483648` | Bytes of pcapng sipnab reads into memory for embedded names and TLS secrets. **A memory-exhaustion guard on untrusted input.** Raising it to N lets ONE file claim N bytes of this host's RAM — roughly 2N while `--strip-secrets` writes its copy — on nothing but a file size, before sipnab can tell the file is a capture at all. Raise it for captures you produced; leave it for captures someone sent you. `--max-metadata-file-bytes` overrides it |
| `max_gunzip_bytes` | integer | `1073741824` | Bytes a gzip-compressed capture may inflate to where sipnab does the inflating: the embedded names and TLS secrets read out of a `.pcapng.gz`, the copy `--strip-secrets` rewrites, and the whole capture in the browser build. libpcap inflates the packet stream of a `-I capture.pcap.gz` run and this does not bound it. **A gzip-bomb guard.** Inflation stops one byte past the ceiling, so raising it to N lets a few kilobytes claim N bytes of RAM. Raise it for archives you compressed yourself. `--max-gunzip-bytes` overrides it |
| `max_tcp_buffer` | integer | `65536` | Bytes one SIP/TCP direction may buffer before sipnab flushes it. **The only limit here that destroys data rather than truncating a report.** TCP sets no such ceiling and neither does RFC 3261: on a carrier trunk a message carrying ISUP encapsulation, a long `Record-Route` set or a fat SDP offer passes 64 KiB legitimately, and sipnab then flushes the buffer mid-message so both halves parse as malformed — the peer that sent a valid message is the one reported broken. Raise it on such a trunk. The floor is one SIP header line (8192); below that no message survives, and sipnab refuses the value by name. `--max-tcp-buffer` overrides it |
| `api_max_rows` | integer | `1000` | Rows one list-style REST response returns. The REST counterpart of `mcp_max_rows`, settable for the same reason: the right ceiling belongs to the consumer, not to sipnab. A batch consumer piping `/v1/dialogs` to a file wants every row; a dashboard drawing a table wants far fewer. `--api-max-rows` overrides it. `0` fails validation and names the key |
| `api_rate_limit_per_peer` | integer | `100` | REST requests one client IP may make per second. The limiter counts by source address, so a dashboard polling `/v1/streams` on a short timer, or several collectors behind one NAT, share a single allowance and see `503` (`503` rather than `429` because the limiter runs before authentication, so the refusal says nothing about the credential). `0` disables the cap, the reading `hep_rate_limit` and `mcp_rate_limit_per_peer` also give it. `--api-rate-limit-per-peer` overrides it |
| `metrics_max_conn` | integer | `16` | Metrics scrapes served at once before further ones get `503`. The gate stops a burst of slow clients exhausting threads and taking monitoring down, and sixteen suits one Prometheus; an HA pair, a federating parent, a `remote_write` shard, an alertmanager sidecar and one engineer's `curl` reach it without anything unusual happening. A refused scrape leaves a hole in the series that reads as a capture that died rather than as a busy endpoint, so raise it where several collectors share one sipnab. `--metrics-max-conn` overrides it. `0` fails validation and names the key: the gate would then refuse every scrape |
| `max_tracked_peers` | integer | `4096` | Distinct peers one rate-limit window holds, across every surface sipnab meters: HEP source addresses and MCP callers. Past it sipnab REFUSES a peer it has not already seen this second rather than waving it through, so on a collector aggregating from more agents than this the surplus never enters the capture. Raise it there. The floor is 2, and sipnab refuses a smaller value by name: at 1 the first peer to send in a window takes the only slot and sipnab turns every other peer away for the rest of it |

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

The compaction pair — `idle_compact_after_secs` and
`keep_messages_per_idle_dialog` — is where a limit discards a ladder sipnab
already holds, so a call that went quiet shows fewer messages than crossed the
wire. sipnab warns once per run when this first happens. The retention logs
(`max_audio_frames`, `max_lost_sequences`) drop their oldest entries as they
fill. Every other key here refuses to take something in.

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
| `dns_cache_entries` | integer | `4096` | Reverse-DNS results (positive and negative) held at once. Past the cap sipnab drops the oldest entry, so a capture touching more hosts than this -- a carrier edge, a peering point, or any long `--reverse-dns` window -- keeps re-looking-up addresses it already resolved. Nothing reports that: a dropped lookup only shows as an address displayed unresolved, so the symptom is names that flicker. The worker queue's depth follows this figure; sipnab derives it rather than taking a second number. `--dns-cache-entries` overrides it |
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
