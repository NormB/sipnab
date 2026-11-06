# Ask each call's rtpengine engine

Several rtpengine engines can sit behind one SIP proxy. The proxy picks an
engine for each call, and it can move a call to another engine in the middle
of the call. `--rtpengine-control` names one engine, so a question about a
call that another engine carries goes to the wrong engine.

sipnab can learn each call's engine in two ways:

- **From rtpengine's control traffic.** Every `offer` the proxy sends goes to
  one engine and names the call. sipnab reads that request from a capture on
  the proxy's host, or from the HEP copy each engine sends. This needs no map
  of media addresses. See
  [Take each call's engine from the control traffic](#take-each-calls-engine-from-the-control-traffic).
- **From the call's SDP.** Each engine writes its own media address into the
  SDP it rewrites. sipnab reads that address and asks the engine that carries
  the call, by a map of media addresses and port ranges.

When sipnab saw an `offer` for the call, that engine is the answer. Otherwise
the SDP map answers, and otherwise `--rtpengine-control`. Use this page when:

- the relay sessions view shows `Unknown call-id` for calls that do have
  media;
- you need the media counters of one call, and the call is on another engine;
- a call moved to another engine, and you suspect the old engine still holds
  a session for it.

To ask one relay about itself, read
[Ask a media relay about itself](relay-statistics.md) first. This page adds
the engine choice to the questions described there.

## What sipnab asks, and where

| Question | Asked of |
|---|---|
| One call: `GET /v1/relay/stats/call/{call_id}`, `compare/{call_id}`, `holdings/{call_id}`, the MCP `query_relay`, `relay_stats` and `relay_compare` tools with a `call_id`, the TUI relay view of a call, `--relay-compare`, and each `query` the sessions view sends | The engine the call's newest `offer` reached, when sipnab saw one and an ng engine row allows it; else the engine the call's newest SDP names |
| Which calls each engine holds: `--relay-holdings`, `GET /v1/relay/holdings`, `query_relay` without a `call_id`, and the `list` of the sessions view (`--relay-sessions`, `GET /v1/relay/sessions`, `query_relay` with `sessions: true`, the TUI's `H`) | `--rtpengine-control` and every engine an engine row or an ng engine row names, each answer shown on its own |
| The relay's own counters: `--relay-stats`, `--relay-stats-list`, `--relay-stats-interval`, `GET /v1/relay/stats` and `stats/names`, `relay_stats` without a `call_id` | `--rtpengine-control` only |
| Startup reconciliation, which names the calls behind media already flowing ([Let sipnab name rtpengine's media](rtpengine-sipnab.md)) | `--rtpengine-control` only |
| A call whose SDP sipnab has not seen, in the sessions view | The engine whose `list` names the call, or `--rtpengine-control` when none does |
| A call whose SDP sipnab has not seen, any other question | `--rtpengine-control` |

Each answer says why it went where it went. `--relay-stats-call` and
`--relay-sessions` ask before sipnab reads any SIP, so they see no SDP. A TUI,
REST or MCP run that captures the signaling sees it.

## Before you start

- **On each rtpengine engine:**
  - a `listen-ng` address that the sipnab host can reach. rtpengine's control
    protocol has no authentication, so allow only the sipnab host to reach it.
  - the media address the engine writes into SDP. That is its `interface`
    setting, or the advertised address after `!` in it, for example
    `interface = 192.0.2.5!203.0.113.5`.
  - a port range, `port-min` and `port-max`. Engines that advertise one
    public address need port ranges that do not overlap. sipnab tells such
    engines apart by port alone.
  - nothing else. sipnab sends only `list` and `query`, and `statistics` to
    `--rtpengine-control` for the relay-statistics requests. None of them
    changes a call.
- **On the SIP proxy: nothing to change.** OpenSIPS with several engines in
  its `rtpengine_sock` set, or Kamailio with several `rtpengine` nodes, picks
  the engine as before.
- **sipnab must see the SIP on both sides of the proxy**: the message that
  reaches the proxy and the message the proxy sends on. Capture on the proxy's
  host (`-d <device>`), or have the proxy send HEP to a sipnab listener
  (`-L <addr>`). A capture of one side only sees the engine's address in one
  direction, which matters only for
  [`--rtpengine-trust-sdp-address`](#use-the-sdp-address-without-a-map).
- **A live source.** Asking transmits, so sipnab asks only on a run that
  captures an interface or listens for HEP. A run that reads a capture file
  never asks.
- **`--rtpengine-control <listen-ng address>`** of one engine. It answers the
  questions in the table that are not about one call.
- **For REST**, start the server with `--api-allow-relay-query`. **For MCP**,
  start it with `--mcp-allow-relay-query`.
- **Build.** Every release binary has it. A source build needs the `native`
  feature, which the default build includes.

The examples use these addresses. Replace them with yours.

| | Media address in SDP | Ports | `listen-ng` |
|---|---|---|---|
| Engine A | `203.0.113.5` | 30000-39999 | `192.0.2.5:2223` |
| Engine B | `203.0.113.5` | 40000-49999 | `192.0.2.6:2223` |

## How sipnab finds the engine in the SDP

A call through an anchoring relay carries four SDP bodies at the proxy: the
caller's own, the engine's rewrite of it sent to the callee, the callee's own,
and the engine's rewrite of that sent to the caller. Measured on
[`tests/fixtures/opensips-proxy-signaling.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/opensips-proxy-signaling.pcap), a call through OpenSIPS and
one rtpengine:

| Message | SDP media |
|---|---|
| INVITE, caller to proxy | `198.51.100.21:6000`, the caller |
| INVITE, proxy to callee | `198.51.100.10:30020`, the engine |
| 200 OK, callee to proxy | `198.51.100.20:6000`, the callee |
| 200 OK, proxy to caller | `198.51.100.10:30018`, the engine |

sipnab reads the `c=` address and the port of the first `m=` line of each
body, in the order it captured them.

- **With an engine map**, a body belongs to an engine when a row claims its
  address and port. The parties' own addresses match no row.
- The engine of the newest body a row claims is the call's engine. After a
  re-INVITE moves the call, that is the new engine.
- The engine of the newest earlier body with another `listen-ng` address is
  the call's previous engine.
- A call whose SDP names no address a row claims is `engine unknown (no map
  row)`. sipnab asks no engine about it, not even `--rtpengine-control`:
  the map is the list of engines sipnab may ask.

## Write the engine map

Give one row per engine and port range, as
`MEDIA-ADDRESS LOW-HIGH CONTROL-ADDRESS:PORT`. On the command line, quote each
row:

```bash
sudo sipnab -d eth0 \
  --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-engine '203.0.113.5 30000-39999 192.0.2.5:2223' \
  --rtpengine-engine '203.0.113.5 40000-49999 192.0.2.6:2223'
```

Or keep the rows in the config file, `[relay] engines`:

```toml
[relay]
engines = [
  "203.0.113.5 30000-39999 192.0.2.5:2223",
  "203.0.113.5 40000-49999 192.0.2.6:2223",
]
```

- `--rtpengine-engine` rows add to `[relay] engines`.
- sipnab accepts a `->` between the port range and the control address, as in
  `203.0.113.5 30000-39999 -> 192.0.2.5:2223`.
- Write an IPv6 media address plain and an IPv6 control address in
  brackets: `2001:db8::5 30000-39999 [2001:db8::10]:2223`.
- One engine can have several rows, for several media addresses.
- sipnab refuses two rows that claim one address and port, because a call
  there would have two engines.
- `--rtpengine-control` can be one of the engines in the map, or another one.
  sipnab lists it with the others either way, and asks it once.

## Ask about a call

The output in this section came from this build of sipnab with two scripted
engines on loopback, the fake `ng` responder sipnab's own tests use, on
`127.0.0.2:2223` (engine A) and `127.0.0.3:2223` (engine B). Each answered
`query` with a recorded rtpengine 12.5.1 reply. The SIP reached sipnab over
HEP: one call's first offer and answer on engine A's ports, then a re-INVITE
that moved it to engine B's. The commands use the addresses in the table
above. The output shows the loopback addresses it came from, `127.0.0.2:2223`
for engine A and `127.0.0.3:2223` for engine B.

Start a server that sees the SIP, with the map and the REST opt-in:

```bash
sudo sipnab -N -d eth0 \
  --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-engine '203.0.113.5 30000-39999 192.0.2.5:2223' \
  --rtpengine-engine '203.0.113.5 40000-49999 192.0.2.6:2223' \
  --api 127.0.0.1:18764 --api-allow-relay-query
```

Ask for one call's counters. The relay label says which engine answered and
which row chose it:

```bash
curl -s "http://127.0.0.1:18764/v1/relay/stats/call/moved-1@192.0.2.21" | jq '{outcome, relay}'
```

```json
{
  "outcome": "ok",
  "relay": "relay (rtpengine at 127.0.0.3:2223), chosen by engine row 203.0.113.5 40000-49999 127.0.0.3:2223 for SDP media 203.0.113.5:40012, call moved-1@192.0.2.21"
}
```

The call's newest SDP named `203.0.113.5:40012`, which the second row claims,
so sipnab asked engine B and not `--rtpengine-control`.

A call whose SDP names media no row claims is not asked of any engine:

```json
{
  "outcome": "not_configured",
  "detail": "call other-1@192.0.2.21: engine unknown (no map row): no engine row claims the call's SDP media 192.0.2.21:6000, 203.0.113.9:30010, 192.0.2.20:6000, 203.0.113.9:30012, 203.0.113.9:40010, 203.0.113.9:40012; nothing was asked"
}
```

`compare/{call_id}`, `holdings/{call_id}`, the MCP tools, the TUI and
`--relay-compare` choose the same way. Over MCP, `relay_stats` with
`{"call_id": "moved-1@192.0.2.21"}` answered:

```json
{
  "relay_address": "127.0.0.3:2223",
  "outcome": "ok",
  "engine": "chosen by engine row 203.0.113.5 40000-49999 127.0.0.3:2223 for SDP media 203.0.113.5:40012"
}
```

`relay_address` is the engine asked. `engine` says why. The answer leaves it
out when the run has no engine rule.

## List the calls every engine holds

```bash
sipnab -N -L 127.0.0.1:0 --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-engine '203.0.113.5 30000-39999 192.0.2.5:2223' \
  --rtpengine-engine '203.0.113.5 40000-49999 192.0.2.6:2223' \
  --relay-holdings 2>/dev/null
```

```text
Holdings of relay (rtpengine at 127.0.0.2:2223), asked 2026-11-05T17:59:20.119782970+00:00
1 call held.
Call-ID
------------------
moved-1@192.0.2.21

Holdings of relay (rtpengine at 127.0.0.3:2223), asked 2026-11-05T17:59:20.119782970+00:00
2 calls held.
Call-ID
-------------------
moved-1@192.0.2.21
only-b-1@192.0.2.21

Held by several engines: moved-1@192.0.2.21
```

- Each engine gets a `list` and a block of its own. An engine that does not
  answer gets a line saying so, and the others' blocks still print.
- The run exits 0 when at least one engine answered, and 1 when none did.
- `--json` and `GET /v1/relay/holdings` add `engines`, each engine's own
  answer, and `held_by_several_engines`, beside `call_ids`, which holds every
  Call-ID once. `query_relay` without a `call_id` carries the same three.

## See whether media reaches each call's engine

The sessions view lists every engine, then queries each call on its own
engine:

```bash
sipnab -N -L 127.0.0.1:0 --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-engine '203.0.113.5 30000-39999 192.0.2.5:2223' \
  --rtpengine-engine '203.0.113.5 40000-49999 192.0.2.6:2223' \
  --relay-sessions 2>/dev/null
```

```text
Sessions of relay (rtpengine at 127.0.0.2:2223), relay (rtpengine at 127.0.0.3:2223), asked 2026-11-05T18:10:16.347476084+00:00 (relay_reported)
reachable; 2 calls listed; queried 2 of 2 (scan)
Engine relay (rtpengine at 127.0.0.2:2223): reachable; 1 call listed
Engine relay (rtpengine at 127.0.0.3:2223): reachable; 2 calls listed
Note: a relay keeps a call it was told to delete for its delete delay (30 s by default) and its answer does not mark it; a call sipnab did not see end in SIP may have ended up to about 30 s ago.
Note: stalled means no packet for more than 2 s while another socket of the same call received one; silence suppression, comfort noise, hold and loss bursts were not measured and can also produce it.

moved-1@192.0.2.21  held by several engines  from callee-tag-1: flowing; from caller-tag-1: flowing
only-b-1@192.0.2.21  from callee-tag-1: flowing; from caller-tag-1: flowing

Call moved-1@192.0.2.21 (relay_reported)
Asked relay (rtpengine at 127.0.0.2:2223) (sipnab has seen no SDP for this call; this engine's list names it).
Held by several engines.
```

That is the start of the answer. Each call's socket table follows.
`--relay-sessions` asks before it reads any SIP, so it has seen no SDP: it
asks each call of the first engine whose list names it. `held by several
engines` marks a Call-ID that two engines list. A run that sees the SIP asks
each call of the engine its SDP names, as below.

## Find a session left on the old engine

After a re-INVITE moves a call, the new engine holds it, and the old engine
should have released it. Add `--relay-previous-engine` to a run that sees the
SIP, and the sessions view asks both:

```bash
sudo sipnab -N -d eth0 \
  --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-engine '203.0.113.5 30000-39999 192.0.2.5:2223' \
  --rtpengine-engine '203.0.113.5 40000-49999 192.0.2.6:2223' \
  --relay-previous-engine \
  --api 127.0.0.1:18764 --api-allow-relay-query
```

```bash
curl -s "http://127.0.0.1:18764/v1/relay/sessions?call_id=moved-1@192.0.2.21" | jq '.calls[0].engine'
```

```json
{
  "asked": "relay (rtpengine at 127.0.0.3:2223)",
  "chosen_by": "map_row",
  "held_by_several_engines": true,
  "listed_by": [
    "relay (rtpengine at 127.0.0.2:2223)",
    "relay (rtpengine at 127.0.0.3:2223)"
  ],
  "previous": {
    "chosen_by": "map_row",
    "holds": true,
    "outcome": "ok",
    "reason": "chosen by engine row 203.0.113.5 30000-39999 127.0.0.2:2223 for SDP media 203.0.113.5:30012",
    "relay": "relay (rtpengine at 127.0.0.2:2223)"
  },
  "reason": "chosen by engine row 203.0.113.5 40000-49999 127.0.0.3:2223 for SDP media 203.0.113.5:40012"
}
```

- `asked` is the engine the newest SDP names, and `previous` is the engine
  the SDP named before the move. `previous.holds` is true: the old engine
  still holds the call.
- `held_by_several_engines` is true when two engines hold the Call-ID, by
  their lists or by their answers.
- In the TUI, the call's view prints the previous engine on a line that
  starts `Previous engine` and names its relay and row, and ends `still
  holds this call; a session was left on the old engine.`, then `Held by
  several engines.`
- The answer has `engine` only when the run has an engine rule. Each
  queried call has one, and so does each call in `not_queried`, with
  `listed_by` and `held_by_several_engines`. The top level adds `engines`,
  each engine's own answer to `list`.

rtpengine keeps a deleted call for its delete delay, 30 s by default. A call
that moved a few seconds ago can still read `held by several engines`. Ask
again after the delay before you treat the old engine's session as left
behind.

## Use the SDP address without a map

`--rtpengine-trust-sdp-address <CONTROL-PORT>` asks the engine at the media
address the call's SDP names, on the control port you give. Use it only when
every SDP writer on the captured network is yours.

**Risk.** sipnab then sends `list` and `query` to an address it read from
captured traffic. Anyone who can put SDP on that network can choose where
sipnab sends them. A map does not have this risk: sipnab asks only the engines
its rows name.

- An address counts as an engine's only when sipnab saw it in both a request's
  SDP and a response's. That is what an anchoring relay's rewrite looks like
  at the proxy. sipnab sees a party's own address one way only. A capture of
  one side of the proxy sees the engine one way, and the call reads `engine
  unknown (no address seen both ways)`.
- sipnab asks the engine of the newest such sighting, and the one before a move
  is the previous engine, as with a map.
- It needs `--rtpengine-control`, and sipnab refuses it beside
  `--rtpengine-engine` or `[relay] engines`. There is no config key.
- `list` goes to `--rtpengine-control` only. sipnab never sends `list` to an
  address it learned from SDP.

With SDP that named `127.0.0.3` both ways, and `--rtpengine-trust-sdp-address
2223`:

```json
{
  "outcome": "ok",
  "relay": "relay (rtpengine at 127.0.0.3:2223), chosen from SDP media 127.0.0.3:40012, trusted as the engine's address, call only-b-1@192.0.2.21"
}
```

## Take each call's engine from the control traffic

The proxy sends each call's `offer` to one engine, and the `offer` names the
call's Call-ID. When sipnab sees that request, it knows the engine the proxy
picked, with no map of media addresses. It also sees:

- **a moved call:** a later `offer` for the same Call-ID at another engine;
- **a leftover session:** an engine the call moved off that never received a
  `delete` for it after its `offer`.

sipnab sees the requests in one of two ways, and you choose by where sipnab
runs:

| sipnab runs on | It reads | What names the engine |
|---|---|---|
| The SIP proxy's host | The proxy's requests, captured on their way to each engine | The address the proxy sent the request to, the engine's `listen-ng` |
| An rtpengine host, or a separate host | Each engine's HEP copy of the requests (`homer-enable-ng = true`) | The engine's `homer-id`, which each HEP copy carries |

### What sipnab trusts, and what it asks

Both kinds of evidence come from captured traffic, so neither is permission to
send. sipnab asks an engine only when you listed it:

- **`--rtpengine-ng-engine '[HOMER-ID] LISTEN-NG'`**, repeatable, or
  `[relay] ng_engines` in the config file. `2001 192.0.2.5:2223` names the
  engine that sends HEP with `homer-id = 2001`. `192.0.2.6:2223` names an
  engine seen only in captured requests.
- For a captured request, an address that `--rtpengine-control` or an
  `--rtpengine-engine` row names counts as listed too.

An `offer` that reached an engine you did not list reads `engine not listed`,
as `not_configured`, and sipnab asks nothing about that call. It does not ask
another engine in its place, because the traffic says the call is not there.
This is the safe default: anyone who can put a datagram on the captured
network could otherwise choose where sipnab sends `query`.

- The newest `offer` by capture time chooses the engine. A `delete` alone
  chooses nothing.
- sipnab remembers the newest 16 `offer` and `delete` requests of each call,
  for as many calls as the dialog limit allows (`--limit`), at most
  `MAX_SIGHTING_CALLS` (16,384). Past that it forgets the call it saw first,
  and a forgotten `offer` can no longer mark a call as moved.
- sipnab copies only `offer` and `delete` into its evidence. `answer`,
  replies, and the `query` and `list` that sipnab itself sends (rtpengine
  copies those too) change nothing.
- With no `offer` seen for a call, the SDP map answers as before, and with no
  map, `--rtpengine-control`.
- `--rtpengine-ng-engine` needs `--rtpengine-control`, as the other engine
  rules do. It can stand alone or beside an `--rtpengine-engine` map.
- `--relay-holdings` and the sessions view also ask every engine an ng engine
  row names for its `list`.

### sipnab on the SIP proxy's host

sipnab captures the proxy's ng requests on the way out. Nothing changes on the
engines or the proxy.

1. Give every engine the same `listen-ng` port. sipnab reads a captured
   request only on the port of `--rtpengine-control`, because a bare ng
   datagram carries no credential. A request to another port is not read.
2. Start sipnab with a capture filter that admits that port, and list each
   engine:

   ```bash
   sudo sipnab -N -d eth0 \
     --rtpengine-control 192.0.2.5:2223 \
     --rtpengine-ng-engine 192.0.2.6:2223 \
     --relay-previous-engine \
     --api 127.0.0.1:18764 --api-allow-relay-query \
     'udp port 5060 or udp port 2223'
   ```

   `--rtpengine-control` counts as listed already, so it needs no row of its own.
3. Place a call. Ask about it:

   ```bash
   curl -s "http://127.0.0.1:18764/v1/relay/stats/call/cap-1@192.0.2.21" | jq -r '.outcome, .relay'
   ```

Measured with two rtpengine 12.5.1 engines on `127.0.0.2:42223` and
`127.0.0.3:42223`, sipnab capturing on `lo`, and a call offered to the first
engine and then to the second:

```text
ok
relay (rtpengine at 127.0.0.3:42223), chosen by the newest ng offer for this call, which reached listen-ng 127.0.0.3:42223; listen-ng 127.0.0.2:42223 never received a delete for this call after its offer (a leftover session), call cap-1@192.0.2.21
```

### sipnab on an rtpengine host

Each engine sends a HEP copy of every control request to sipnab, so sipnab
does not need to see the proxy. On each engine, add these lines to the
`[rtpengine]` section of `/etc/rtpengine/rtpengine.conf`, with a `homer-id`
unique to the engine, and restart it:

```ini
homer = 192.0.2.40:9060
homer-protocol = udp
homer-id = 2001
homer-enable-ng = true
```

- `192.0.2.40` is the host where sipnab runs. On that host's own engine you
  can write `homer = 127.0.0.1:9060`.
- sipnab needs `homer-enable-ng = true`. Without it rtpengine sends RTCP
  statistics only, and they name no call.
- Start sipnab before the engines send, because rtpengine stops sending to a
  destination that refused it. See
  [Let sipnab name rtpengine's media](rtpengine-sipnab.md#when-something-does-not-work).

Start sipnab with its HEP listener, and one row per engine that names its
`homer-id` and `listen-ng`:

```bash
sudo sipnab -N -d any -L 192.0.2.40:9060 \
  --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-ng-engine '2001 192.0.2.5:2223' \
  --rtpengine-ng-engine '2002 192.0.2.6:2223' \
  --relay-previous-engine \
  --api 127.0.0.1:18764 --api-allow-relay-query
```

Measured with two rtpengine 12.5.1 engines, `homer-id` 2001 on
`127.0.0.1:42223` and 2002 on `127.0.0.1:42224`, both sending HEP to sipnab on
`127.0.0.1:49060`, and a call offered to 2001 and then to 2002:

```bash
curl -s "http://127.0.0.1:18764/v1/relay/stats/call/moved-1@192.0.2.21" | jq -r .relay
```

```text
relay (rtpengine at 127.0.0.1:42224), chosen by the newest ng offer for this call, which reached homer-id 2002 (ng engine row 2002 127.0.0.1:42224); homer-id 2001 never received a delete for this call after its offer (a leftover session), call moved-1@192.0.2.21
```

**If the engines already send HEP to Homer**, rtpengine takes one `homer`
destination, so pointing it at sipnab takes it away from Homer. Keep Homer
instead, and run sipnab where the copies pass: on an engine's host, or on the
Homer host. sipnab reads a HEP copy on its way to another collector only on
UDP port 9060. Capture that port:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 192.0.2.5:2223 \
  --rtpengine-ng-engine '2001 192.0.2.5:2223' \
  'udp port 9060'
```

A copy read this way is not authenticated. Prefer the listener, with
`--hep-auth`, where you can.

### sipnab on a separate host

This is the same as on an rtpengine host: each engine sends HEP to the sipnab
host, and sipnab names the engine by `homer-id`. Two things differ:

- `homer` in each engine's `rtpengine.conf` is the sipnab host's address, and
  the network must let UDP from each engine reach it.
- Each `listen-ng` address in an `--rtpengine-ng-engine` row must be one the
  sipnab host can reach. An engine that binds its `listen-ng` to its loopback
  address cannot answer a question from another host. sipnab still reports its calls,
  moves and leftover sessions by `homer-id`.

The HEP copy also reports the `listen-ng` address the engine bound, which is
often `127.0.0.1`. sipnab shows it in the `engine not listed` message to help
you write the row. It never sends to it.

### Find a leftover session from the control traffic

With `--relay-previous-engine`, the sessions view asks each leftover engine
you listed whether it still holds the call:

```bash
curl -s "http://127.0.0.1:18764/v1/relay/sessions?call_id=moved-1@192.0.2.21" | jq '.calls[0].engine'
```

Measured on the two engines above, before any `delete`:

```json
{
  "asked": "relay (rtpengine at 127.0.0.1:42224)",
  "chosen_by": "ng_offer",
  "held_by_several_engines": true,
  "leftovers": [
    {
      "engine": "homer-id 2001",
      "relay": "relay (rtpengine at 127.0.0.1:42223)",
      "status": "confirmed"
    }
  ],
  "listed_by": [
    "relay (rtpengine at 127.0.0.1:42223)",
    "relay (rtpengine at 127.0.0.1:42224)"
  ],
  "previous": {
    "chosen_by": "ng_offer",
    "holds": true,
    "outcome": "ok",
    "reason": "chosen by the newest ng offer for this call, which reached homer-id 2001 (ng engine row 2001 127.0.0.1:42223)",
    "relay": "relay (rtpengine at 127.0.0.1:42223)"
  },
  "reason": "chosen by the newest ng offer for this call, which reached homer-id 2002 (ng engine row 2002 127.0.0.1:42224)"
}
```

- `leftovers` lists each engine the call moved off with no `delete` after
  its `offer`. `status` is `confirmed` (it still holds the call), `released`
  (it does not), `not_asked`, `unreachable` or `suspect`.
- Without `--relay-previous-engine`, a leftover reads `not_asked` with
  `add --relay-previous-engine to ask it`. An engine no row names reads
  `not_asked` with `no --rtpengine-ng-engine row names it`, and sipnab never
  asks it.
- In the TUI, the call's view prints a line such as `Leftover session on
  homer-id 2001 (relay (rtpengine at 127.0.0.1:42223)): confirmed, it still
  holds this call.`
- When a `delete` for the call reaches the old engine, the answer drops
  the leftover. The old engine still answers `query` for its delete delay,
  30 s by default, so `previous.holds` can stay true for that long.

## Check that it worked

- A question about a captured call names the engine and the row that chose
  it, for example `chosen by engine row 203.0.113.5 40000-49999 192.0.2.6:2223
  for SDP media 203.0.113.5:40012`.
- `--relay-holdings` prints one `Holdings of` block per engine, and every
  engine in your map is there.
- A call you know is on engine B reads `Asked relay (rtpengine at
  192.0.2.6:2223)` in the sessions view, not engine A.
- With ng engine rows, a question about a call placed after sipnab started
  names `chosen by the newest ng offer for this call`, and the engine.

## When it does not work

- **`call other-1@192.0.2.21: engine unknown (no map row): no engine row
  claims the call's SDP media 192.0.2.21:6000, 203.0.113.9:30010,
  192.0.2.20:6000, 203.0.113.9:30012, 203.0.113.9:40010, 203.0.113.9:40012;
  nothing was asked`.** The call's SDP names media no row claims. The message
  lists every address and port sipnab saw for the call. Add a row for
  the engine's address and port range. If only the parties' addresses are
  listed, sipnab saw no message the engine rewrote: check that the capture
  sees both sides of the proxy, or that the proxy anchors the call's media at
  all.
- **`the default engine (--rtpengine-control): sipnab has seen no SDP for
  this call`** or **`sipnab has seen no SDP for this call; this engine's list
  names it`.** sipnab holds no SDP for the call: the run started after the
  call's last offer and answer, the call's SIP went past another capture
  point, or the run is `--relay-sessions` or `--relay-stats-call`, which ask
  before sipnab reads any SIP. Ask from a TUI, REST or MCP run that sees the call's
  next re-INVITE, or ask that engine with `--rtpengine-control`.
- **`Unknown call-id` from the engine sipnab chose.** The engine does not
  hold the call. Check that each row's port range is that engine's own
  `port-min` and `port-max`; a range that belongs to another engine sends the
  question to the wrong one.
- **`Engine relay (rtpengine at 127.0.0.9:2223): unreachable: relay
  (rtpengine at 127.0.0.9:2223) did not answer (no reply from
  127.0.0.9:2223 within 2s); asked, nothing came back` in the sessions
  status.** That engine did not answer its `list`. The calls the other
  engines hold are still in the answer. Check that the sipnab host can reach
  that `listen-ng` address.
- **`--rtpengine-engine (or [relay] engines) needs --rtpengine-control as
  well: that engine answers the questions that are not about one call (the
  relay's statistics, the poll, startup reconciliation) and about a call whose
  SDP sipnab has not seen. Name one engine's listen-ng address, for example
  --rtpengine-control 192.0.2.5:2223`** and exit 2 (1 for `[relay] engines`).
  Add `--rtpengine-control` with one engine's `listen-ng` address.
- **`--rtpengine-engine / [relay] engines: engine rows "203.0.113.5
  30000-40000 192.0.2.5:2223" and "203.0.113.5 40000-49999 192.0.2.6:2223"
  overlap: both claim media 203.0.113.5 port 40000, so a call there has no
  single engine`** and exit 2 (1 when both rows are in `[relay] engines`).
  Make the port ranges the engines' own, which do not overlap.
- **`error: invalid value '203.0.113.5 40000 192.0.2.6:2223' for
  '--rtpengine-engine <MEDIA LOW-HIGH CONTROL>': engine row "203.0.113.5 40000
  192.0.2.6:2223": "40000" is not a port range LOW-HIGH with 1 <= LOW <= HIGH
  <= 65535`** and exit 2. The row is not three fields, or one field does not
  parse. The message names the field. A bad row in `[relay] engines` reads,
  for example, `invalid config value: [relay] engines: engine row
  "203.0.113.5 39999-30000 192.0.2.5:2223": "39999-30000" is not a port range
  LOW-HIGH with 1 <= LOW <= HIGH <= 65535`, and exits 1.
- **`error: the following required arguments were not provided:
  --rtpengine-control <ADDR>`** with `--relay-holdings` or `--relay-sessions`.
  Those flags need `--rtpengine-control`, with or without a map.
- **`--relay-previous-engine needs an engine rule to name a previous
  engine: add --rtpengine-engine rows, [relay] engines, or
  --rtpengine-trust-sdp-address`** and exit 2. Add engine rows, or drop the
  flag.
- **`--rtpengine-trust-sdp-address and an engine map (--rtpengine-engine or
  [relay] engines) are two rules for one question; the map is an allowlist and
  trusting SDP is none. Give one of them`** and exit 2. Keep one rule.
- **`call only-a-1@192.0.2.21: engine not listed (homer-id 2001): the newest
  ng offer for this call reached homer-id 2001, and no --rtpengine-ng-engine
  row names it (the engine reports listen-ng 127.0.0.1:42223); nothing was
  asked`.** Add `--rtpengine-ng-engine '2001 <listen-ng>'` with an address
  the sipnab host can reach.
- **`call cap-3@192.0.2.21: engine not listed (127.0.0.4:42223): the newest
  ng offer for this call was sent to 127.0.0.4:42223, an address sipnab saw
  only in captured traffic; list it with --rtpengine-ng-engine to ask it;
  nothing was asked`.** If that address is one of your engines, add
  `--rtpengine-ng-engine 127.0.0.4:42223`.
- **`the default engine (--rtpengine-control): sipnab has seen no ng offer
  for this call`.** The proxy sent the call's `offer` before sipnab started, or it
  did not reach sipnab:
  - On the proxy's host, check that the capture filter admits the
    `listen-ng` port and that each engine listens on the port of
    `--rtpengine-control`.
  - With HEP, check `homer-enable-ng = true` and that sipnab listened before
    the engine sent.
  - A call already up when sipnab started has no `offer` to see. The SDP map
    and `--rtpengine-control` still answer for it.
- **A question goes to the SDP map's engine although the engine sends HEP.**
  The HEP copy carried no capture id, so it names no engine. Set `homer-id` in
  the engine's `rtpengine.conf`.
- **`--rtpengine-ng-engine / [relay] ng_engines: ng engine rows "2001
  192.0.2.5:2223" and "2001 192.0.2.6:2223" both name homer-id 2001, so a
  call there has no single engine`** and exit 2 (1 when both rows are in
  `[relay] ng_engines`). Give each engine its own `homer-id` and address.

[Error messages](errors.md#media-relays-rtpengine-and-rtpproxy) lists every
refusal with its exit code.

## See also

- [Ask a media relay about itself](relay-statistics.md): the questions this
  page routes.
- [Let sipnab name rtpengine's media](rtpengine-sipnab.md): startup
  reconciliation, which asks `--rtpengine-control` only.
- [CLI reference](cli-reference.md#rtp): `--rtpengine-engine`,
  `--rtpengine-ng-engine`, `--rtpengine-trust-sdp-address` and
  `--relay-previous-engine`.
- [Config reference](config-reference.md#relay): `[relay] engines` and
  `[relay] ng_engines`.
