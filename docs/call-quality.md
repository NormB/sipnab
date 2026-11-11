# Measure call quality

sipnab scores every RTP stream it captures: a MOS, the E-model R-factor
behind it, jitter and packet loss. It keeps the score for each few seconds
of the call as well, so you can see when quality changed, and it keeps what
the far end reported over RTCP apart from what sipnab measured.

Use this page to answer "how did this call sound, and when did it go wrong?"
For one-way audio, dead air and codec mismatches, see
[Troubleshooting](troubleshooting.md). For where the MOS comes from and
which codecs have a published basis for it, see
[MOS and codecs](mos-and-codecs.md).

## Before you start

- **No change to any other system.** sipnab measures the RTP it captures.
  Nothing on the SIP server, the phones or the relay needs to change.
- **RTCP is optional.** When the endpoints send RTCP, sipnab also reports
  what the far end said. Without it, every figure is sipnab's own.
- **The capture must hold the media.** A capture of signaling only has no
  streams to score. Live capture needs root or the capture capabilities
  `sudo sipnab --setup-caps` grants once. Reading a file needs neither.
- **Build.** Every build scores streams. The REST route needs the `api`
  feature, the MCP tools need `mcp`, and the terminal UI needs `tui`. All
  three are in the release binaries; `sipnab --version` lists them.

The examples read
[`tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap),
a public capture of one call with a lossy stream, and
[`tests/fixtures/rtcp-xr-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/rtcp-xr-call.pcap),
a generated call whose far end sends RTCP. The output came from sipnab
0.5.232.

## Read each stream's score

`--json-dialogs` prints each call with its streams. Pick the quality fields
with `jq`:

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --json-dialogs --no-cli-print 2>/dev/null \
  | jq -c '.streams[]? | {ssrc, codec, packets, loss_pct: (.loss_pct*100|round/100), jitter_ms: (.jitter_ms*100|round/100), mos: (.mos*100|round/100), r_factor: (.r_factor*10|round/10)}' \
  | sort -u
```

```json
{"ssrc":"0xb72a7104","codec":"PCMU","packets":790,"loss_pct":0.13,"jitter_ms":0.56,"mos":4.33,"r_factor":89.6}
{"ssrc":"0xbee0f2ed","codec":"PCMU","packets":205,"loss_pct":64.29,"jitter_ms":0.25,"mos":1.02,"r_factor":8.6}
{"ssrc":"0xbee0f2ed","codec":"PCMU","packets":2,"loss_pct":0,"jitter_ms":0.03,"mos":4.36,"r_factor":90.8}
```

- `mos` runs from 1.0 to 4.5, higher is better.
- `r_factor` is the ITU-T G.107 rating sipnab converts to the MOS, 0 to 100.
- `loss_pct` and `jitter_ms` are what sipnab measured on the wire.
- `mos_grounded: false` on a stream means its codec has no published
  impairment value and the MOS is a placeholder.
  [MOS and codecs](mos-and-codecs.md#tell-a-scored-mos-from-a-placeholder)
  covers it.

Here one direction of the call lost 64 % of its packets and scores 1.0,
while the other direction scores 4.33.

## See when the quality changed

A whole-stream figure averages a bad minute into a good call. Each stream
also carries `quality_intervals`, one entry per interval, five seconds by
default:

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --json-dialogs --no-cli-print 2>/dev/null \
  | jq -c '.streams[]? | select(.ssrc=="0xbee0f2ed" and .packets>100) | .quality_intervals[] | {timestamp: .timestamp[11:19], packets, loss_pct: (.loss_pct|round), mos: (.mos*10|round/10), verdict}'
```

```json
{"timestamp":"07:13:11","packets":114,"loss_pct":54,"mos":1,"verdict":"degraded"}
{"timestamp":"07:13:16","packets":17,"loss_pct":93,"mos":1,"verdict":"degraded"}
```

Five seconds hides a burst shorter than itself. `--quality-interval` sets
the interval, from 1 to 300 seconds (`[limits] quality_interval_secs` in the
config file):

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --quality-interval 1 --json-dialogs --no-cli-print 2>/dev/null \
  | jq -c '.streams[]? | select(.ssrc=="0xbee0f2ed" and .packets>100) | .quality_intervals[] | {timestamp: .timestamp[11:19], packets, loss_pct: (.loss_pct|round), mos: (.mos*10|round/10), verdict}'
```

```json
{"timestamp":"07:13:07","packets":38,"loss_pct":24,"mos":1.4,"verdict":"degraded"}
{"timestamp":"07:13:08","packets":51,"loss_pct":0,"mos":4.4,"verdict":"acceptable"}
{"timestamp":"07:13:11","packets":6,"loss_pct":95,"mos":1,"verdict":"degraded"}
{"timestamp":"07:13:16","packets":22,"loss_pct":91,"mos":1,"verdict":"degraded"}
{"timestamp":"07:13:17","packets":50,"loss_pct":0,"mos":4.4,"verdict":"acceptable"}
```

At one second the stream shows clean seconds between the bursts, which the
five-second view averaged away. An interval with no packets has no entry.
A finer interval costs memory, not history: the trend still covers an hour
of call time.

`--max-lost-sequences` (`[limits] max_lost_sequences`, default 1000) sets
how many lost sequence numbers sipnab keeps per stream for the loss map and
the burst and gap analysis below.

## Watch quality in the terminal UI

```bash
sipnab -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap
```

Press `Tab` for the RTP streams, then `D` for the **Quality dashboard**. It
ranks the streams worst MOS first and draws the selected stream's trend:

```text
┌ Quality dashboard ──────────────────────────────────────────────────────────────
│  Streams: 3 (0 active)   Avg MOS: 3.2   Worst: 1.0   With loss: 2
│
│    MOS   Rating   Jitter   Loss%   Packets  Codec    Stream
│▶ · 1.0   Bad       0.2ms  64.29       205  PCMU     ZDYzOWVlNjEwM2NjZTBjNzliNmM1ZTNiOGZjNWFhN2E.
│  · 4.3   Good      0.6ms   0.13       790  PCMU     ZDYzOWVlNjEwM2NjZTBjNzliNmM1ZTNiOGZjNWFhN2E.
│  · 4.4   Good      0.0ms   0.00         2  PCMU     ZDYzOWVlNjEwM2NjZTBjNzliNmM1ZTNiOGZjNWFhN2E.
│
│  Trend (selected, 5s intervals, oldest → newest)
│  MOS:    ▁▁
│  Jitter: ▁▁
│  Loss:   ██
```

In the first column, `●` marks an active stream and `·` an idle one. On a
live capture with a call up, every stream of that call shows `●`.

Press `L` for the **Packet loss map** of the selected stream. It shows where
in the stream the packets went missing:

```text
┌ Packet loss map ────────────────────────────────────────────────────────────────
│  SSRC 0xBEE0F2ED   192.168.10.41:64508 → 192.168.10.40:49848
│  Loss 64.29%   369 lost / 574 packets
│  Bursts 3   Pattern Bursty   Avg burst 2473ms
│
│███                      ▓█████████████████████████████░    ▒███████████████████
│4513                                                               4800
```

Three long bursts mean the path dropped everything for seconds at a time, a
different fault from a steady trickle of loss. `Esc` returns to the
dashboard, and `Enter` there opens **Stream detail**: the MOS, the delay
sipnab scored it with, the quality intervals and the burst and gap analysis for
the stream.

## Find the bad streams over REST

`GET /v1/streams?mos_below=` returns the streams scored below a MOS:

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --api 127.0.0.1:8080 --no-cli-print
```

```bash
curl -s 'http://127.0.0.1:8080/v1/streams?mos_below=3.0' \
  | jq -c '{total, ungrounded_excluded, streams: [.streams[] | {ssrc, codec, mos: (.mos*100|round/100), loss_pct: (.loss_pct*100|round/100), r_factor: (.r_factor*10|round/10)}]}'
```

```json
{"total":1,"ungrounded_excluded":0,"streams":[{"ssrc":"0xbee0f2ed","codec":"PCMU","mos":1.02,"loss_pct":64.29,"r_factor":8.6}]}
```

`ungrounded_excluded` counts streams whose MOS is a placeholder. The filter
never selects them. The MCP `rtp_stats` tool answers the same question for
an agent, with `min_mos` and `max_mos`.

## Read what the far end reported

An endpoint that sends RTCP reports its own view of the stream it receives:
loss, jitter, and in an RTCP XR VoIP Metrics block, its own R-factor, MOS,
round trip and jitter-buffer discards. sipnab keeps that apart, under
`endpoint_reported` in the MCP `media_diagnostics` answer. It never moves sipnab's
own loss or jitter.

Start an MCP server on the capture and call `media_diagnostics` for the call:

```bash
sipnab -N --mcp -I tests/fixtures/rtcp-xr-call.pcap --quiet
```

`media_diagnostics { "call_id": "rtcp-xr-1@192.0.2.30" }` answers with one
entry per stream. The caller's stream, selected with the `jq` filter
`.streams[] | select(.ssrc=="0x0a0a0a0a") | {ssrc, packets, delay, endpoint_reported: (.endpoint_reported | del(.note))}`,
reads:

```json
{
  "ssrc": "0x0a0a0a0a",
  "packets": 475,
  "delay": {
    "assumed": false,
    "one_way_ms": 90.0,
    "source": "per far end"
  },
  "endpoint_reported": {
    "reception_report": {
      "cumulative_lost": 25,
      "fraction_lost_pct": 5.078125,
      "jitter_ms": 2.0,
      "reporter_ssrc": "0x0b0b0b0b",
      "reports_seen": 2,
      "round_trip_ms": null
    },
    "voip_metrics": {
      "burst_duration_ms": 0,
      "discard_rate_pct": 3.125,
      "end_system_delay_ms": 40,
      "gap_duration_ms": 10000,
      "loss_rate_pct": 5.078125,
      "mos_cq": 3.7,
      "mos_lq": 3.8,
      "r_factor": 78,
      "reporter_ssrc": "0x0b0b0b0b",
      "reports_seen": 2,
      "round_trip_delay_ms": 180
    }
  }
}
```

Read it in three parts:

- **`reception_report`** is the far end's RTCP receiver report about this
  stream: 25 packets lost, about 5 %. sipnab's own count agrees: 475 of the
  500 packets reached the capture.
- **`voip_metrics`** is the far end's RTCP XR block. Two figures in it are
  out of any capture's reach: `discard_rate_pct`, the packets that arrived
  and that the far end's jitter buffer threw away, and the far end's own
  `r_factor` and MOS.
- **`delay`** is the one-way delay behind sipnab's own MOS. Here it is half
  the XR block's 180 ms round trip, `per far end`. Without RTCP it reads
  `"source": "assumed"` and 100 ms.

The answer also carries a `note`: nothing authenticates RTCP, and a report
describes the path from the sender to the reporter, which on a mid-path
capture is not the segment sipnab sees. Where the far end and sipnab
disagree, the difference says where on the path the fault is.
[MOS and codecs](mos-and-codecs.md#what-sipnab-computes-the-score-from)
explains how to read it.

In the TUI, the same stream's Stream detail scores it on that delay and adds
the far end's figures at the bottom:

```text
  MOS: 3.1 (Poor)    Jitter: 0.0ms    Loss: 5.00%    RTT: 180ms    (delay 90ms per far end)
```

```text
── Reported by far end (RTCP XR) ──────────────────────────────────────────────────
  Endpoint's own claim, not sipnab's measurement (reporter SSRC 0x0B0B0B0B, 2 reports)
  MOS-LQ: 3.8    MOS-CQ: 3.7    R factor: 78    Ext R: n/a
  Loss: 5.08%    Discard: 3.12%    Burst density: 0.0%    Gap density: 5.1%
  Burst duration: 0ms    Gap duration: 10000ms    Round-trip: 180ms    End-system: 40ms
```

## Set the thresholds to your network

Eight thresholds decide when a figure counts as a warning or as bad. They
color the TUI's quality columns, set the buckets of the Prometheus MOS,
jitter and loss histograms, and set the loss and jitter limits of the
`--problems` alias. Put them in the config file:

```toml
[quality]
mos_warn = 4.0
mos_bad = 3.2
jitter_warn_ms = 20.0
jitter_bad_ms = 50.0
loss_warn_pct = 1.0
loss_bad_pct = 3.0
rtt_warn_ms = 150.0
rtt_bad_ms = 300.0
```

Or pass them for one run as `--mos-warn`, `--mos-bad`, `--jitter-warn-ms`,
`--jitter-bad-ms`, `--loss-warn-pct`, `--loss-bad-pct`, `--rtt-warn-ms` and
`--rtt-bad-ms`. A flag overrides the file.

To check that sipnab took them, serve metrics and read the MOS histogram's
buckets. `--api` keeps a file run serving after it has read the file:

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --mos-warn 4.0 --mos-bad 3.2 \
  --metrics 127.0.0.1:9090 --api 127.0.0.1:8080 --no-cli-print
```

```bash
curl -s http://127.0.0.1:9090/metrics | grep '^sipnab_mos_bucket'
```

```text
sipnab_mos_bucket{le="1"} 0
sipnab_mos_bucket{le="2"} 1
sipnab_mos_bucket{le="2.5"} 1
sipnab_mos_bucket{le="3.2"} 1
sipnab_mos_bucket{le="3.5"} 1
sipnab_mos_bucket{le="4"} 1
sipnab_mos_bucket{le="4.5"} 3
sipnab_mos_bucket{le="5"} 3
sipnab_mos_bucket{le="+Inf"} 3
```

The `le="3.2"` bucket is your `mos_bad`. With the shipped values it reads
`le="3"`.

sipnab refuses thresholds that cannot work, names the pair, and exits 2:

```text
--mos-warn (3) is below --mos-bad (3.5); MOS bands run downward, so no score could ever be a warning
```

Thresholds change what sipnab colors and selects, never the measurement.

## Run a command when quality drops

`--on-quality-exec` runs a command when a stream's MOS falls below
`--quality-threshold` (default 3.0). sipnab passes the stream in
environment variables, never in the command string:

| Variable | Holds |
|---|---|
| `SIPNAB_SSRC` | the stream's SSRC, in hexadecimal with a `0x` prefix |
| `SIPNAB_MOS` | the MOS at that moment |
| `SIPNAB_JITTER` | jitter, in milliseconds |
| `SIPNAB_LOSS` | loss, in percent |
| `SIPNAB_STREAM_JSON` | the whole stream, as the JSON stream object |

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --quality-threshold 3.0 \
  --on-quality-exec 'echo "$SIPNAB_SSRC mos=$SIPNAB_MOS jitter=$SIPNAB_JITTER loss=$SIPNAB_LOSS" >> alerts.log' \
  --no-cli-print
```

```bash
sort alerts.log
```

```text
0xb72a7104 mos=2.63 jitter=5.0 loss=7.1
0xb72a7104 mos=2.71 jitter=6.0 loss=6.7
0xb72a7104 mos=2.79 jitter=6.8 loss=6.2
0xb72a7104 mos=2.86 jitter=6.5 loss=5.9
0xb72a7104 mos=2.93 jitter=6.1 loss=5.6
0xb72a7104 mos=2.99 jitter=5.8 loss=5.3
0xbee0f2ed mos=1.00 jitter=1.0 loss=75.0
0xbee0f2ed mos=1.00 jitter=1.0 loss=80.0
0xbee0f2ed mos=1.00 jitter=1.1 loss=85.7
0xbee0f2ed mos=1.01 jitter=0.9 loss=70.6
```

- The check runs on every RTP packet, against the stream's score so far. So
  a stream that ends well, such as `0xb72a7104` at 4.33, can still fire early
  in the call.
- `--exec-rate-limit` caps the commands per second (default 10). The run
  ends with a warning that counts the commands run and the events the limit
  skipped; this run ran 10 and skipped 200.
- The command runs in `sh -c`. sipnab reports a failing command, never
  retries it, and never stops the capture for it.

## Check that it worked

sipnab scored the capture's media when every stream it found carries a `mos`.
Count both:

```bash
sipnab -N -I tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap --json-dialogs --no-cli-print 2>/dev/null \
  | jq -c -s '[.[].streams[]?] | {streams: length, scored: (map(select(.mos != null)) | length)}'
```

```json
{"streams":3,"scored":3}
```

`{"streams":0,"scored":0}` means the capture holds no RTP that sipnab tied to
a call. [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap), a capture of signaling
only, gives that answer.

## When something does not work

- **The MOS reads `(delay 100ms assumed, not measured)`** in Stream detail,
  or `delay.assumed: true` in MCP. Nothing supplied a one-way delay, so the
  score uses 100 ms. Declare yours with `--one-way-delay`, or capture the
  endpoints' RTCP. [MOS and codecs](mos-and-codecs.md#what-sipnab-computes-the-score-from)
  lists the order sipnab tries.
- **A stream reports `mos_grounded: false`.** Its codec has no published
  impairment value. Declare one in `[media.codec_ie]`
  ([MOS and codecs](mos-and-codecs.md#declare-an-impairment-factor-for-a-codec)).
- **Loss looks high on every call at once.** The capture host may have
  dropped the packets. See
  [Tune capture on a busy server](tuning-capture.md).
- **A warning that starts `IMPOSSIBLE RATE:`.** sipnab read the same traffic
  twice, usually a capture and its copy in one `-I` directory. Every count
  and rate in that run is too high by that factor. Reading a directory that
  held two copies of `sip-rtp-g711.pcap` logged:

  ```text
  WARN sipnab::app::batch: IMPOSSIBLE RATE: 2 stream(s) carry more payload than their codec can produce — worst is PCMU ssrc=343da99b 10.0.2.15:27942 -> 10.0.2.20:6000 at 2.0x its ceiling. The most common cause is the same traffic read twice: a directory holding a capture and its backup, or one call captured at two hops. Counts and rates in this run are inflated by that factor. sipnab does not de-duplicate, because two vantage points on one call are a legitimate input.
  ```
- **`invalid value '0' for '--quality-interval <SECONDS>': 0 is not in
  1..=300`** and exit 2. The interval is 1 to 300 seconds.
- **No `endpoint_reported` key.** No RTCP for that stream reached the
  capture. Its absence means the far end reported nothing, not that
  everything was fine.
