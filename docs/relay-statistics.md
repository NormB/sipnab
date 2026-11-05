# Ask a media relay about itself

A media relay keeps its own counters: the packets it relayed, the sessions it
holds, and its own loss and jitter. sipnab can ask an rtpengine relay for
them, and put them beside what sipnab measured on the wire.

Use this page when you suspect the relay itself:

- calls sound bad and the relay may be dropping packets;
- the relay may be holding sessions that nobody released;
- you want the relay's count for one call beside your capture's.

Every answer here is the relay's own claim, labeled `relay_reported`. sipnab
never adds it to, or subtracts it from, a number it measured. To name the
calls behind the media on a relay, see
[Let sipnab name rtpengine's media](rtpengine-sipnab.md) instead.

## Before you start

- **The relay is rtpengine.** sipnab asks over rtpengine's `ng` control
  protocol. sipnab sends rtpproxy nothing, so none of these requests apply to
  rtpproxy ([Let sipnab name rtpproxy's media](rtpproxy-sipnab.md)).
- **No change to rtpengine.** sipnab asks on the control address rtpengine
  already listens on, its `listen-ng` setting. Every request only reads:
  `statistics`, `list` and `query`. Nothing here can create, change or delete
  a call.
- **No change to the SIP proxy, Homer or anything else.**
- **The control address must be reachable from sipnab.** rtpengine's control
  protocol has no authentication, so run sipnab on the relay's own machine, or
  on a host your firewall already lets reach `listen-ng`.
- **A live source.** Asking transmits, so sipnab asks only on a run that
  captures an interface (`-d`) or listens for HEP (`-L`). A run that reads a
  capture file never asks.
- **Privileges.** Capturing an interface needs root or the capture
  capabilities `sudo sipnab --setup-caps` grants once.
- **Build.** Every release binary can ask. A source build needs the `native`
  feature, which the default build includes. The REST routes need `api` and
  the MCP tools need `mcp`; `sipnab --version` lists both when the binary
  carries them.

The examples use `127.0.0.1:22222` for the relay's `listen-ng` address and
`eth0` for the interface. Replace them with yours. The output on this page
came from sipnab 0.5.232 against rtpengine 12.5.1 (the Debian 13 package),
with the relay's address written as `127.0.0.1` and the SIP test clients'
address as `192.0.2.21`.

## Ask the relay for its counters

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats --duration 1
```

sipnab asks once, prints the answer, and captures for `--duration` seconds.
The answer is long: rtpengine 12.5.1 reports 303 counters. The header names
the relay, when it answered, and the tier:

```text
Relay statistics (rtpengine at 127.0.0.1:22222, asked 2026-11-03T15:38:21Z) — relay_reported counts
  result                                       ok
  statistics.currentstatistics.sessionsown     1
  statistics.totalstatistics.managedsessions   6
  statistics.totalstatistics.relayedpacketerrors 0
  statistics.totalstatistics.relayedpackets    51643
  statistics.totalstatistics.timeoutsessions   1
  statistics.totalstatistics.uptime            85077
```

That is a few lines of the answer. Keep only the lines you want with `grep`:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats --duration 1 2>/dev/null \
  | grep -E 'sessionsown|relayedpackets |packets_lost|uptime'
```

```text
  statistics.currentstatistics.sessionsown     0
  statistics.interfaces.0.packets_lost         0
  statistics.totalstatistics.relayedpackets    51451
  statistics.totalstatistics.uptime            85061
  statistics.voip_metrics.packets_lost         0
```

Read these first:

| Counter | What it says |
|---|---|
| `statistics.currentstatistics.sessionsown` | Calls the relay holds now |
| `statistics.totalstatistics.relayedpackets` | Packets relayed since the relay started |
| `statistics.totalstatistics.relayedpacketerrors` | Packets the relay failed to relay |
| `statistics.interfaces.0.packets_lost` | Loss the relay counted on its first interface |
| `statistics.totalstatistics.uptime` | Seconds since the relay started |

The counters are cumulative and reset when rtpengine restarts. A small
`relayedpackets` can mean a quiet relay or one that restarted a minute ago.
`uptime` tells them apart.

### List the statistics the relay knows

The names depend on the rtpengine version. Ask for the names alone:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats-list --duration 1 2>/dev/null | head -3
```

```text
Statistics rtpengine at 127.0.0.1:22222 knows (303 names, asked 2026-11-03T15:19:04Z) — the relay listed these in a statistics reply
  result
  statistics.controlstatistics.proxies.0.answercount
```

The header says how sipnab learned the names: the relay listed them. sipnab
holds no table of its own.

### Ask about one call

Give a Call-ID the relay holds:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats-call '1-29@192.0.2.21' --duration 1 2>/dev/null \
  | grep -E '^Relay|totals'
```

```text
Relay statistics (rtpengine at 127.0.0.1:22222, call 1-29@192.0.2.21, asked 2026-11-03T15:19:03Z) — relay_reported counts
  totals.RTCP.bytes                            0
  totals.RTCP.errors                           0
  totals.RTCP.packets                          0
  totals.RTP.bytes                             530104
  totals.RTP.errors                            0
  totals.RTP.packets                           3082
```

Without the `grep`, the answer also lists each side of the call by its tag:
the codec, the relay's port, and the packets and bytes per SSRC.

### Watch the counters move

One answer is a snapshot. To see a counter move, poll on a timer:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats-interval 2 --duration 5 2>/dev/null \
  | grep -E '^Relay|sessionsown|relayedpackets |uptime'
```

```text
Relay statistics (rtpengine at 127.0.0.1:22222, polled 2026-11-03T15:19:22Z, every 2s) — relay_reported counts
  statistics.currentstatistics.sessionsown     2
  statistics.totalstatistics.relayedpackets    14117
  statistics.totalstatistics.uptime            83938
Relay statistics (rtpengine at 127.0.0.1:22222, polled 2026-11-03T15:19:24Z, every 2s) — relay_reported counts
  statistics.currentstatistics.sessionsown     2
  statistics.totalstatistics.relayedpackets    14517
  statistics.totalstatistics.uptime            83940
```

- Each reading says `polled` and names the interval.
- The interval is 1 to 3600 seconds. Nothing polls unless you give one.
- sipnab sends the next request only after the previous answer, so a slow
  relay slows the cadence rather than piling up requests. A poll whose round
  trip takes longer than the interval logs a warning that the cadence has
  slipped.
- A cumulative counter that is lower than at the previous poll logs a warning
  that the relay probably restarted. The counters after it start from an
  unknown point.
- Only the command line polls. REST and MCP do not offer it.

### Read the answer as JSON

`--json` prints one object per answer, on one line. Here `grep` picks out its
envelope and two of its counters:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats --json --duration 1 2>/dev/null \
  | tail -1 \
  | grep -oE '"(obtained_at|origin|relay)":"[^"]*"|\{"name":"statistics\.(currentstatistics\.sessionsown|totalstatistics\.uptime)","tier":"[a-z_]*","value":"[^"]*"\}'
```

```text
"obtained_at":"2026-11-03T19:13:24Z"
"origin":"asked"
"relay":"rtpengine at 127.0.0.1:22222"
{"name":"statistics.currentstatistics.sessionsown","tier":"relay_reported","value":"0"}
{"name":"statistics.totalstatistics.uptime","tier":"relay_reported","value":"97979"}
```

The object carries `relay`, `origin` (`asked`, or `polled` under
`--relay-stats-interval`), `obtained_at`, `refusals`, and `statistics`: one
entry per counter, with its `name`, its `tier` and its `value` as the relay
wrote it.

## List the calls the relay holds

To see which calls the relay is carrying right now, without capturing
anything:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-holdings 2>/dev/null
```

```text
Holdings of relay (rtpengine at 127.0.0.1:22222), asked 2026-11-03T15:18:50.189704516+00:00
1 call held.
Call-ID
----------------
1-29@192.0.2.21
```

- sipnab sends one `list` request, prints the answer and exits 0. It reads no
  packet.
- The relay returns at most 32 Call-IDs unless you raise the limit with
  `--relay-holdings-max <CALLS>`. When it returns as many as you asked for,
  the answer says the relay may hold more.
- `--json` prints the body `GET /v1/relay/holdings` returns, with
  `"truncated"` true or false.

A leaked session is one the relay still holds after its call ended. Compare
this list with the calls your SIP proxy still has up. A Call-ID the relay
holds and the proxy does not is a candidate. rtpengine removes a session
whose media stopped only after its RTP `timeout` setting has passed, so a
call that ended a short time ago can still appear.

## See whether media reaches the relay

For each call the relay holds, sipnab can say per direction whether the
relay is receiving that party's media. Use it during a "no audio" or
"one-way audio" incident: it names the party whose media never reached the
relay, from one answer of the relay's and on the relay's own clock.

### What it needs

- **On the relay: nothing to change.** sipnab sends rtpengine's `list` and
  `query` on its `listen-ng` address. Neither creates, changes or deletes a
  call.
- **`--rtpengine-control <listen-ng address>`** on the sipnab command line,
  and a live source (`-d` or `-L`), as for every request on this page.
- **For REST**, start the server with `--api-allow-relay-query`. **For MCP**,
  start it with `--mcp-allow-relay-query`. Without the opt-in the request
  sends nothing.
- **To mark a hung-up call `ended`**, sipnab must see that call's SIP: a TUI,
  REST or MCP run that captures the signaling. A `--relay-sessions` run asks
  before it reads any packet, so it can only say that the relay may still
  list a call for about 30 s after it ends.

The output in this section came from this build of sipnab against the
harness relay, rtpengine 12.5.1 in userspace, with calls placed by SIPp
through OpenSIPS. This page writes the relay's address as `192.0.2.11` and
the SIP test clients' as `192.0.2.21`.

### Ask from the command line

```bash
sipnab -N -L 127.0.0.1:0 --rtpengine-control 192.0.2.11:22222 --relay-sessions 2>/dev/null
```

`-L 127.0.0.1:0` is a HEP listener that receives nothing. It is enough to
make the run live, so it needs no privileges. sipnab sends one `list`, then
one `query` per held call, up to `--relay-holdings-max` (32 by default),
prints the answer and exits 0:

```text
Sessions of relay (rtpengine at 192.0.2.11:22222), asked 2026-11-04T16:01:54.067925771+00:00 (relay_reported)
reachable; 2 calls listed; queried 2 of 2 (scan)
Note: a relay keeps a call it was told to delete for its delete delay (30 s by default) and its answer does not mark it; a call sipnab did not see end in SIP may have ended up to about 30 s ago.
Note: stalled means no packet for more than 2 s while another socket of the same call received one; silence suppression, comfort noise, hold and loss bursts were not measured and can also produce it.

sg2-nomedia-1-104@192.0.2.21  from 104SIPpTag001: never received; from 1SIPpTag0110: flowing
sg2-twoway-1-105@192.0.2.21  from 105SIPpTag091: flowing; from 1SIPpTag0111: flowing

Call sg2-nomedia-1-104@192.0.2.21 (relay_reported)
sipnab did not see its SIP dialog end; the relay may still list a call for about 30 s after it ends.
from 104SIPpTag001 to 192.0.2.11:30038: never received
from 1SIPpTag0110 to 192.0.2.11:30000: flowing
Tag            Relay socket      Kind  In pkts  In bytes  In errs  Out pkts  Out bytes  Out errs  Last packet  Forwarding
-------------------------------------------------------------------------------------------------------------------------
104SIPpTag001  192.0.2.11:30038  rtp   0        0         0        243       41796      0         1793808109   userspace
104SIPpTag001  192.0.2.11:30039  rtcp  0        0         0        0         0          0         1793808109   userspace
1SIPpTag0110   192.0.2.11:30000  rtp   245      42140     0        0         0          0         1793808114   userspace
1SIPpTag0110   192.0.2.11:30001  rtcp  0        0         0        0         0          0         1793808109   userspace
```

The first call's caller sent no media, and the answer says so: the relay
counted 0 packets in on that party's socket and never confirmed it. The
second call's media reaches the relay both ways. Each call's table, the
second one's included, follows.

How to read a direction:

| Verdict | Meaning |
|---|---|
| `flowing` | packets are arriving on that party's RTP socket |
| `never received` | the socket counted 0 packets in, and the relay never marked it `confirmed` |
| `no packet for N s` (`stalled`) | its last packet is more than 2 s behind the newest one of any RTP socket of the same call, in the same answer |
| `not reported by this relay version` (`not_reported`) | the relay's answer lacked the counters, the last-packet time or the flags |

- **`stalled` compares sockets of one call.** When every socket of a call
  stops together, none trails another, so the call still reads `flowing`.
  The `Last packet` column is the relay's own time in seconds.
- **A call with an early media branch** (a parallel fork that sent early
  media) shows its counters and no verdict. rtpengine can count the answered
  party's media on the early branch's socket, and a verdict per socket would
  call a live party silent.
- **`Forwarding`** is `kernel` when the relay flags the socket `kernelized`
  without `no kernel support`, and `userspace` otherwise.
- **Absent is not zero.** A counter the relay did not report reads
  `not reported`, and the JSON leaves it out.

To ask about one call only, with one `list` and one `query`:

```bash
sipnab -N -L 127.0.0.1:0 --rtpengine-control 192.0.2.11:22222 --relay-sessions --relay-sessions-call sg2-twoway-1-105@192.0.2.21 --json 2>/dev/null
```

`--json` prints one object on one line, the body of `GET /v1/relay/sessions`.
Here it is pretty-printed and shortened to one tag and one socket:

```json
{
  "calls": [
    {
      "call_id": "sg2-twoway-1-105@192.0.2.21",
      "directions": [
        {
          "from_tag": "105SIPpTag091",
          "local_address": "192.0.2.11",
          "local_port": 30014,
          "media_index": 1,
          "verdict": "flowing"
        },
        {
          "from_tag": "1SIPpTag0111",
          "local_address": "192.0.2.11",
          "local_port": 30048,
          "media_index": 1,
          "verdict": "flowing"
        }
      ],
      "outcome": "ok",
      "sip_dialog": "not_seen_ended",
      "tags": [
        {
          "in_dialogue_with": [
            "1SIPpTag0111"
          ],
          "is_media_subscriber": false,
          "sockets": [
            {
              "egress": {
                "bytes": 135020,
                "errors": 0,
                "packets": 785
              },
              "endpoint": "192.0.2.21:6000",
              "ingress": {
                "bytes": 135020,
                "errors": 0,
                "packets": 785
              },
              "kernel": "userspace",
              "kind": "rtp",
              "last_packet": 1793808124,
              "local_address": "192.0.2.11",
              "local_port": 30014,
              "media_index": 1
            }
          ],
          "tag": "105SIPpTag091"
        }
      ]
    }
  ],
  "cap": 32,
  "held": 2,
  "list_limit": 32,
  "not_queried": [
    {
      "call_id": "sg2-nomedia-1-104@192.0.2.21",
      "sip_dialog": "not_seen_ended"
    }
  ],
  "notes": [
    "a relay keeps a call it was told to delete for its delete delay (30 s by default) and its answer does not mark it; a call sipnab did not see end in SIP may have ended up to about 30 s ago",
    "stalled means no packet for more than 2 s while another socket of the same call received one; silence suppression, comfort noise, hold and loss bursts were not measured and can also produce it"
  ],
  "obtained_at": "2026-11-04T16:02:04.870332099+00:00",
  "outcome": "ok",
  "reach": "ok",
  "relay": "relay (rtpengine at 192.0.2.11:22222)",
  "scan": false,
  "stall_seconds": 2,
  "tier": "relay_reported",
  "truncated": false
}
```

`not_queried` names the held calls this answer did not ask about, so a call
never drops out of the answer. `truncated` is true when `list` returned as
many Call-IDs as it asked for, and the relay may then hold more.

### Ask over REST and MCP

Start a server with both opt-ins:

```bash
sipnab -N -L 127.0.0.1:0 --rtpengine-control 192.0.2.11:22222 \
  --api 127.0.0.1:18731 --api-allow-relay-query \
  --mcp --mcp-transport http --mcp-bind 127.0.0.1:18732 --mcp-allow-relay-query
```

`GET /v1/relay/sessions` takes `call_id` (one call to query) and `scan=true`
(every held call, up to 32). Without `scan`, sipnab asks only `list` and
`call_id`:

```bash
curl -s "http://127.0.0.1:18731/v1/relay/sessions?call_id=sg2-nomedia-1-104@192.0.2.21" | jq '.calls[0].directions'
```

```json
[
  {
    "from_tag": "104SIPpTag001",
    "local_address": "192.0.2.11",
    "local_port": 30038,
    "media_index": 1,
    "verdict": "never_received"
  },
  {
    "from_tag": "1SIPpTag0110",
    "local_address": "192.0.2.11",
    "local_port": 30000,
    "media_index": 1,
    "verdict": "flowing"
  }
]
```

Over MCP, call `query_relay` with `{"sessions": true, "scan": true}`. The
answer has `"asked": "sessions"`, `"outcome": "sessions"`, and the same
snapshot under `sessions`. The two calls above came back as:

```text
sg2-nomedia-1-104@192.0.2.21 [('104SIPpTag001', 'never_received'), ('1SIPpTag0110', 'flowing')]
sg2-twoway-1-105@192.0.2.21 [('105SIPpTag091', 'flowing'), ('1SIPpTag0111', 'flowing')]
```

That listing is each `calls[]` entry's `call_id` and its `directions`, read
from the tool's JSON.

### Tell a call that ended from one that is up

rtpengine keeps a hung-up call for its delete delay, 30 s by default, and
answers for it as it did while the call was up. Asked a few seconds after
the first call above hung up, the relay still listed it:

```text
sg2-nomedia-1-104@192.0.2.21  from 104SIPpTag001: never received; from 1SIPpTag0110: flowing
```

Its callee still reads `flowing`: that socket was the newest of its call, so
nothing trailed it.

A run that sees the SIP marks such a call. Start the server capturing the
bridge the SIP crosses:

```bash
sudo sipnab -N -d br-0b7ba286bc5b --rtpengine-control 192.0.2.11:22222 --api 127.0.0.1:18741 --api-allow-relay-query
```

Then a 5 s call, asked about after its BYE, reads:

```bash
curl -s "http://127.0.0.1:18741/v1/relay/sessions?call_id=sg2-short-1-114@192.0.2.21" | jq '.calls[0] | {call_id, sip_dialog, directions}'
```

```json
{
  "call_id": "sg2-short-1-114@192.0.2.21",
  "sip_dialog": "ended",
  "directions": [
    {
      "from_tag": "114SIPpTag001",
      "local_address": "192.0.2.11",
      "local_port": 30040,
      "media_index": 1,
      "verdict": "never_received"
    },
    {
      "from_tag": "1SIPpTag0112",
      "local_address": "192.0.2.11",
      "local_port": 30036,
      "media_index": 1,
      "verdict": "flowing"
    }
  ]
}
```

`br-0b7ba286bc5b` is the harness's Docker bridge. Replace it with the
interface your SIP crosses.

### Watch it in the terminal UI

Open the relay view with `S`, then press `H`:

```text
┌ Relay sessions — what the relay holds
│Sessions of relay (rtpengine at 192.0.2.11:22222), asked 2026-11-04T16:03:55.240602811+00:00 (relay_reported)
│reachable; 1 call listed; queried 1 of 1
│Note: a relay keeps a call it was told to delete for its delete delay (30 s by default) and its answer does not mark it; a call sipnab did not see end in SIP
│may have ended up to about 30 s ago.
│Note: stalled means no packet for more than 2 s while another socket of the same call received one; silence suppression, comfort noise, hold and loss bursts
│were not measured and can also produce it.
│
│> sg2-tui-1-121@192.0.2.21  from 121SIPpTag091: flowing; from 1SIPpTag0113: flowing
│
│Enter opens the call under the cursor; a asks every held call once (up to the cap).
```

- While the view is open it asks for the list and the call under the cursor
  every `--relay-stats-interval` seconds, or every 2 s without it
  (`DEFAULT_REFRESH_SECS` (2) in [`src/tui/relay_sessions.rs`](https://github.com/NormB/sipnab/blob/main/src/tui/relay_sessions.rs)). It asks
  nothing once you close it.
- `a` asks about every held call once, up to 32. Up and Down move the
  cursor, and Enter opens that call's directions and socket table.
- In one call's view, `K` sets each relay socket's counts beside what this
  capture saw on it, two tiers named and never subtracted. Captured on the
  harness bridge, starting partway through the call:

```text
Call sg2-tui-1-121@192.0.2.21: relay sockets beside this capture
relay_reported is what the relay counted; sipnab_measured is what this capture saw.
121SIPpTag091 192.0.2.11:30010 (rtp)
  in:  relay_reported 2023  sipnab_measured 768
  out: relay_reported 2023  sipnab_measured 768
121SIPpTag091 192.0.2.11:30011 (rtcp)
  in:  relay_reported 0  sipnab_measured not captured
  out: relay_reported 0  sipnab_measured not captured
```

The relay counts from the start of the call and the capture from when it
started, so the two differ. `not captured` means this capture has no
stream to or from that socket. On a run that captures no media, such as
`-L`, every socket reads `not captured`.

### Check that it worked

- `--relay-sessions` exits 0, and its second line starts `reachable;`.
- Every call the relay holds is in the answer, as a row with verdicts or as
  `not queried`.
- On a call with audio both ways, both directions read `flowing`. If they do
  not, read the troubleshooting list below before suspecting the relay.

### When the sessions answer is not what you expect

- **`--relay-sessions will not ask a relay on a run that reads a file:
  asking transmits. Ask from a live source (-d <device> or -L <addr>).`** and
  exit 2. The run reads a capture file, and sends nothing.
- **`--relay-sessions: unreachable: relay (rtpengine at 192.0.2.11:22299) did
  not answer (no reply from 192.0.2.11:22299 within 2s); asked, nothing came
  back`** and exit 1. No relay answers at that address. Use the relay's
  `listen-ng` value. sipnab sends no `query` after an unanswered `list`.
- **`error: the following required arguments were not provided:
  --rtpengine-control <ADDR>`.** `--relay-sessions` and
  `--relay-sessions-call` need the relay's address.
- **`not_permitted` from `GET /v1/relay/sessions`.** The server lacks
  `--api-allow-relay-query`, or reads a capture file. It sent nothing.
- **A call that hung up still reads `flowing`.** The relay keeps it for its
  delete delay. Ask from a run that sees the SIP, which marks it `ended`.
- **A direction reads `no packet for N s` on a call with audio.** The
  sending phone may suppress silence or send comfort noise, or the call may
  be on hold. Those cases were not measured, and can make a live party trail
  by more than 2 s.
- **A call shows its counters and "early media branch".** The call forked
  and one branch sent early media; read the socket table instead of a
  verdict.
- **A held call reads `not queried`.** The scan stops at the cap, 32 by
  default, the selected call included. Raise it with
  `--relay-holdings-max`, or ask about that call with
  `--relay-sessions-call`.

## Compare the relay's count with your capture

For one call, put the relay's RTP packet count beside the count sipnab
measured. The capture must see the call's media, so run it where the media
passes, here on the relay's own machine:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-compare '1-77@192.0.2.21' --duration 5 2>/dev/null \
  | grep -A3 '^Relay vs capture'
```

```text
Relay vs capture for call 1-77@192.0.2.21 (rtpengine at 127.0.0.1:22222, asked 2026-11-03T16:11:40Z) — differ
  relay                                        818  [relay_reported totals.RTP.packets]
  sipnab                                       996  [sipnab_measured]
  note: the relay counted fewer; a capture that sees both sides of a relay counts each packet more than once -- once arriving at the relay and once leaving it -- so a point upstream AND downstream of the relay reads about twice the relay's own count. A window that does not line up or a relay restart mid-call also gaps them. To compare like for like, capture one leg, or read the relay's per-stream counts.
```

sipnab asks after the capture ends, so its own count is final. A capture on
the relay's machine sees each packet arrive and leave, so here sipnab counted
more than the relay. The note names the cause. When the call was up before
the capture began, the gap runs the other way and the note says so: the
relay counted packets the capture never saw.

Read it with the three loss figures apart:

- the relay's own count (`relay_reported`), for its sockets since it started;
- sipnab's count (`sipnab_measured`), for what reached the capture point;
- the far end's RTCP report (`endpoint_reported`), which nobody can check.

Never subtract one from another. They count different sockets over different
windows. Quote the tier with the number: "the relay reports 40 lost, our
capture measured 3 gaps".

## Ask over REST

The REST server answers the same questions on six routes. They transmit, so
they are off unless you add `--api-allow-relay-query`:

```bash
sudo env SIPNAB_API_KEY="$SIPNAB_API_KEY" sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 \
  --api 127.0.0.1:8080 --api-allow-relay-query
```

```bash
AUTH="Authorization: Bearer $SIPNAB_API_KEY"
```

```bash
curl -s -H "$AUTH" http://127.0.0.1:8080/v1/relay/holdings
```

```json
{"call_ids":["1-37@192.0.2.21","1-45@192.0.2.21","1-29@192.0.2.21"],"kind":"calls","obtained_at":"2026-11-03T15:19:51.410109408+00:00","origin":"asked","outcome":"ok","relay":"relay (rtpengine at 127.0.0.1:22222)","truncated":false}
```

| Route | Answers |
|---|---|
| `GET /v1/relay/stats` | the relay's counters, as `--relay-stats` |
| `GET /v1/relay/stats/names` | the names it knows, as `--relay-stats-list` |
| `GET /v1/relay/stats/call/{call_id}` | one call's counters, as `--relay-stats-call` |
| `GET /v1/relay/compare/{call_id}` | the comparison, as `--relay-compare` |
| `GET /v1/relay/holdings` | the Call-IDs it holds, as `--relay-holdings`; `?max_calls=` raises the limit |
| `GET /v1/relay/holdings/{call_id}` | one call's tags, ports, SSRCs and codec |

Every answer is HTTP 200 with an `outcome` field. Branch on it first: `ok`,
or one of `not_configured`, `not_permitted`, `unreachable`, `refused` and
`suspect`. The comparison carries its two counts and the verdict under
`packets`.

Without `--api-allow-relay-query`, every route refuses. `/v1/relay/holdings`
answers:

```json
{"detail":"this run may not query the relay; it needs a live capture source and --api-allow-relay-query","outcome":"not_permitted","responsibility":"invocation"}
```

The [REST API reference](rest-api.md#get-v1relaystats) gives each route's full
response.

## Let an agent ask

The MCP server has three tools that ask the relay. All three transmit, so
they need the same three things: `--mcp-allow-relay-query`,
`--rtpengine-control`, and a live source.

```bash
sudo sipnab --mcp -N -d eth0 --rtpengine-control 127.0.0.1:22222 --mcp-allow-relay-query --quiet
```

| Tool | Arguments | Answers |
|---|---|---|
| `query_relay` | none, or `call_id` | the Call-IDs the relay holds, or one call's tags and streams |
| `relay_stats` | none, `call_id`, or `names_only: true` | the relay's counters, one call's, or the names it knows |
| `relay_compare` | `call_id` | the relay's count beside sipnab's, with a verdict and a note |

`relay_compare { "call_id": "1-53@192.0.2.21" }`
answers, trimmed:

```json
{"call_id":"1-53@192.0.2.21","delivery_trust":"asked","outcome":"compared","relay_address":"127.0.0.1:22222","relay_reported":{"name":"totals.RTP.packets","value":2112},"sipnab_measured":1188,"schema_version":1}
```

`delivery_trust: "asked"` means sipnab asked the relay over its control
socket, so no third party could have answered. `decode_ng` needs none of the
three opt-ins: it decodes a relay control message already in the capture
([rtpengine relay attribution](rtpengine.md#let-an-agent-ask-the-relay)).

The [relay tool reference](mcp-tools-relay.md) gives each tool's full
response.

## Read the newest poll without asking again

A dashboard or an agent can read the relay's counters without asking the
relay itself. A headless run started with `--relay-stats-interval` keeps its
newest reading, and serves it on `GET /v1/relay/stats/polled` and the MCP tool
`relay_stats_polled`. Only that run's poll talks to rtpengine, however many
readers there are.

**Prerequisites.** Those in [Before you start](#before-you-start), with two
differences:

- Reading sends nothing to the relay. It needs no `--api-allow-relay-query` or
  `--mcp-allow-relay-query`. The poll itself is the operator's, on the command
  line.
- Serve MCP over HTTP (`--mcp --mcp-transport http`) on the polling run. Over
  stdio, sipnab refuses `--relay-stats-interval`, because it prints each
  reading to stdout, which the stdio transport owns.

**Steps.** Start a headless run that polls every five seconds and serves
REST, wait for a reading, and read it. Then stop the run. This example listens
for HEP on `127.0.0.1:9061` as its live source:

```bash
# Run all of these, in order.
sipnab -N -L 127.0.0.1:9061 --rtpengine-control 127.0.0.1:22222 --relay-stats-interval 5 --api 127.0.0.1:8091 --api-key s3cret > /dev/null 2>&1 &
sleep 8
curl -s -H "Authorization: Bearer s3cret" http://127.0.0.1:8091/v1/relay/stats/polled | jq '{outcome, relay, origin, interval_secs, age_secs}'
curl -s -H "Authorization: Bearer s3cret" http://127.0.0.1:8091/v1/relay/stats/polled | jq '.statistics[] | select(.name | endswith("sessionsown"))'
kill $!
```

**Verify.** The first `curl` prints the reading's header:

```json
{
  "outcome": "ok",
  "relay": "rtpengine at 127.0.0.1:22222",
  "origin": "polled",
  "interval_secs": 5,
  "age_secs": 2
}
```

The second prints one of the relay's counters, with its tier:

```json
{
  "name": "statistics.currentstatistics.sessionsown",
  "value": "0",
  "tier": "relay_reported"
}
```

- `outcome` is `ok` once the poll has obtained a reading.
- `age_secs` stays below `interval_secs` while the relay answers.
- An agent calls `relay_stats_polled` with no arguments and gets the same
  fields.

**Troubleshoot.**

- **`"outcome": "not_polling"`.** The run was not started with
  `--relay-stats-interval`, or it is a terminal-interface run: the TUI polls
  only while its relay view is open, and keeps those readings to itself.
- **`"outcome": "no_reading_yet"` with a `last_poll` of `unreachable`.**
  Nothing answers at `--rtpengine-control`. Give it rtpengine's `listen-ng`
  address. The run's log says `did not answer the polled statistics request`.
- **`age_secs` keeps growing past `interval_secs`, beside a `last_poll`.**
  The poll still runs, and the relay stopped answering after the reading
  shown. The reading stays until a newer one replaces it.
- **The run exits with `--relay-stats-interval will not poll a relay on a run
  that reads a file`.** `-I` cannot poll, because polling transmits. Use a
  live source.

The reference entries are
[`GET /v1/relay/stats/polled`](rest-api.md#get-v1relaystatspolled) and
[`relay_stats_polled`](mcp-tools-relay.md#relay_stats_polled).

## Use the terminal UI

Start the TUI with the relay's control address, on a live source:

```bash
sudo sipnab -d eth0 --rtpengine-control 127.0.0.1:22222
```

Press `S` to open the **Relay statistics** view:

- from the call list, it shows the relay's counters;
- from a call's flow view, it shows that call's counters.

The view asks in the background and says that it is asking the relay until
the answer arrives. Inside it:

| Key | Shows |
|---|---|
| `?` | the names the relay knows |
| `H` | the relay sessions: each held call and whether media reaches the relay each way ([see above](#watch-it-in-the-terminal-ui); press again for the counters) |
| `K` | the relay's count beside this capture's, in a call's view only |
| `Esc` or `S` | closes the view |

`K` needs the call's media in the capture. On a machine that sees the SIP
and not the media, it reads:

```text
Relay statistics unavailable — not_configured (invocation)

the relay reports 542 RTP packet(s) for call 1-61@192.0.2.21, but this capture measured none for it; widen the capture filter to include the media
```

## When something does not work

- **`--relay-stats will not ask a relay on a run that reads a file`** (logged
  as an error, exit 0). The run reads a capture file. Ask from a live capture
  with `-d`. The file's analysis still runs.
- **`--relay-holdings will not ask a relay on a run that reads a file`** and
  exit 2. The same, for `--relay-holdings`. Its live sources are `-d` and
  `-L`.
- **`relay at 127.0.0.1:22222 did not answer the statistics request (no reply
  from 127.0.0.1:22222 within 2s)`.** Nothing answers at that address.
  Give `--rtpengine-control` the `listen-ng` value from rtpengine's
  configuration, and check that sipnab can reach it. For the same cause,
  `--relay-holdings` exits 1 with
  `--relay-holdings: unreachable: relay (rtpengine at 127.0.0.1:22222) did not answer (no reply from 127.0.0.1:22222 within 2s); asked, nothing came back`.
- **`Permission denied on 'eth0'`** and exit 1. The capture needs privileges.
  Run with `sudo`, or grant them once with `sudo sipnab --setup-caps`.
- **`not_permitted` from every `/v1/relay/` route.** You started the server
  without `--api-allow-relay-query`, or it reads a capture file.
- **`relay_stats is not available on this server. It transmits, so it needs
  three things`** (the same for `query_relay` and `relay_compare`), as a
  JSON-RPC error with `"reason":"not_enabled"`. The run lacks one of
  `--mcp-allow-relay-query`, `--rtpengine-control` and a live source. A run
  that reads a capture file never has a live source.
- **`--mcp-allow-relay-query: these opt-ins act on the sipnab process or the
  relay`** and exit 2. The run opened the TUI as well as MCP. The TUI's relay
  view and the MCP tools share one permission to transmit, so sipnab refuses
  the MCP opt-in beside the TUI. Add `-N`.
- **The comparison reads `not_configured` and `this capture measured none for
  it`.** The capture did not see the call's media. Capture where the media
  passes, usually on the relay's machine, and check that your capture filter
  admits rtpengine's `port-min` to `port-max` range.
- **`--relay-holdings: suspect: relay (rtpengine at 127.0.0.1:22223): a relay reply could not be trusted: rtpengine reply is not bencode: bencode: 'E' does not begin any bencode value; the reply was discarded and not read`**
  and exit 1. The address is rtpproxy's control socket, or something else
  that is not rtpengine. These requests are for rtpengine.

## See also

- [Let sipnab name rtpengine's media](rtpengine-sipnab.md): tie relay media to
  its call.
- [Attribute media on an rtpengine relay](rtpengine.md): how sipnab decides
  which call a relay stream belongs to, and how far it trusts the relay.
- [Add rtpengine to your voice stack](rtpengine-relay.md): install the relay
  these requests ask.
- [Ask each call's rtpengine engine](relay-engines.md): with several engines
  behind one proxy, ask the engine each call's SDP names.
