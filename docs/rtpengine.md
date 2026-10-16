# Attribute media on an rtpengine relay

You installed sipnab on a media relay and ran a capture. You got a screen full
of orphaned RTP streams. Every packet is there, and none of it says which call
it belongs to. This page fixes that.

**The short version.**

- A standalone relay carries no SIP. So a capture there has media and nothing
  to name it with.
- rtpengine knows the name. Its `ng` control protocol carries the Call-ID and
  the ports it allocated.
- rtpengine can already mirror that control plane to a Homer collector.
- sipnab reads that mirror and ties the media to the call.

A call that was already up when the capture opened left no control message for
the mirror to carry. So `--rtpengine-control` asks the relay for that one
directly.

## The problem, on a relay capture

Both runs below read the same forty RTP packets on the same four sockets. The
only difference is whether the six control-plane packets are in the file.

Without the control plane, everything orphans:

```text
Orphaned Streams:
SSRC         Source                   Destination              Pkts     Duration
--------------------------------------------------------------------------------
0x0a0a0a0a   192.0.2.60:40001         192.0.2.40:38156         10       0s
0x0b0b0b0b   192.0.2.60:40002         192.0.2.40:38664         10       0s
0x0a0a0a0a   192.0.2.40:38664         192.0.2.60:40002         10       0s
0x0b0b0b0b   192.0.2.40:38156         192.0.2.60:40001         10       0s
```

With it, the same media resolves to one call. It also gains a codec, because
the control plane carries the SDP too:

```text
RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps
--------------------------------------------------------------------------------------------------------------------------
0x0a0a0a0a   0    PCMU     8000   192.0.2.60:40001      192.0.2.40:38156      10      0      0.0%    2ms      0s     99
0x0b0b0b0b   0    PCMU     8000   192.0.2.60:40002      192.0.2.40:38664      10      0      0.0%    2ms      0s     99
0x0a0a0a0a   0    PCMU     8000   192.0.2.40:38664      192.0.2.60:40002      10      0      0.0%    2ms      0s     99
0x0b0b0b0b   0    PCMU     8000   192.0.2.40:38156      192.0.2.60:40001      10      0      0.0%    2ms      0s     99

Calls named by a media relay (no SIP for them in this capture):
Call-ID                                                      Streams
---------------------------------------------------------------------
km-670bd208@sipnab                                           4
```

Reproduce both from the committed fixtures:

Without the control plane, every stream orphans:

```sh
sipnab -N -I tests/fixtures/rtpengine-media-only.pcap --report
```

With it, the same media resolves to one call:

```sh
sipnab -N -I tests/fixtures/rtpengine-ng-hep.pcap --report
```

Decoding the mirrored control plane needs a build with the `hep` feature,
which `full` includes. A build without it prints the orphaned table for both
files. `sipnab --version` lists `hep` when the binary carries it.

There are four streams and not two.

- The relay holds its own socket per leg.
- It also holds the far party's on the other side of each.
- All four belong to one call.

## Which method fits your deployment?

Read down the first column and stop at the first row you can satisfy.

| Your situation | Use | Changes rtpengine? | Notes |
|---|---|---|---|
| rtpengine already reports to a Homer collector | Capture on the relay host | **No** | sipnab reads the copy already on the wire. Nothing about your Homer pipeline changes. sipnab cannot authenticate that copy, and reads it only on UDP port 9060 — see [How much a `media-relay` assertion is worth](#how-much-a-media-relay-assertion-is-worth). |
| rtpengine reports nowhere yet | Turn on `--homer-enable-ng`, point it anywhere sipnab can see | Yes, once | The destination can be a collector, or a host that discards the traffic |
| You need it delivered rather than sniffed | `--hep-listen` on sipnab, point rtpengine at it | Yes | Costs you the collector — see the warning below |

Every row here covers control messages that cross the wire while sipnab
runs. None of them reaches a call the relay set up before the capture
opened. For that, add `--rtpengine-control`.

- It asks the relay.
- It runs alongside whichever row you picked.

**rtpengine takes exactly one Homer destination.**

- `--homer` is a single value, not a repeatable option. So "send to the real
  collector and to sipnab" does not exist.
- Anything that points rtpengine at sipnab takes it away from the collector it
  feeds.
- That is why sipnab reads the traffic off the wire by default:
  - A diagnostic tool has no business in a production data path.
  - If sipnab stops, nothing else notices.

## Several rtpengine instances behind one proxy

A proxy that load-balances across a pool of relays puts each call on exactly
one of them. Run **one sipnab per host**:

- The proxy's sipnab sees the SIP.
- Each relay's sipnab sees the media its own host relays.

```text
                        sipnab@proxy
                        (SIP; no media)
                              |
        +---------------------+---------------------+
        |                     |                     |
  sipnab@relay-a        sipnab@relay-b        sipnab@relay-c
  (media it relays)     (media it relays)     (media it relays)
```

Each relay host runs sipnab against its **own local** relay:

```bash
# The same command on relay-a, relay-b and relay-c. Each asks only its own relay.
# The API binds to a non-loopback address so that another machine can query it.
# sipnab refuses a non-loopback API bind without authentication, so --api-key
# is required.
sudo sipnab -d eth0 --rtpengine-control 127.0.0.1:22222 \
  --api 0.0.0.0:8080 --api-key "$SIPNAB_API_KEY"
```

The queries below need the address, the key and a Call-ID. Set them once, on
whichever machine you are running `curl` from.

`$H` interpolates `$KEY`. So set the key first.

- An `$H` built before `$KEY` exists carries an `Authorization` header with no
  token in it.
- Every query below then returns `401`.

```bash
KEY="$SIPNAB_API_KEY"
```

```bash
H="-H 'Authorization: Bearer $KEY'"
```

Then the call you are chasing:

```bash
CALL_ID="1-1966@10.0.2.20"
```

`--rtpengine-control` takes one address.

- A relay can only answer for calls it is carrying.
- So a sipnab asking a relay on another host would get `RelayDoesNotHoldIt`
  for everything.

### Finding a call without asking every relay

You do not have to ask every relay. **The proxy's own SDP names the relay.**
The `c=` address the proxy negotiated is the address of the rtpengine it
steered the call to.

**First, ask the proxy which relay has it.**

```bash
curl -fsS "http://proxy:8080/v1/dialogs/$CALL_ID" $H \
  | jq -r '.sdp_timeline[0] | "\(.media_addr):\(.media_port)"'
# 192.0.2.40:38664
```

**Then ask that one relay, and no others.**

```bash
curl -fsS "http://192.0.2.40:8080/v1/dialogs/$CALL_ID" $H | jq '.streams'
```

A relay that never carried the call answers **404**. A relay that carried the
call answers `200`, with an empty `streams` list when the call had no media.

### Knowing whose answer you are holding

Every node stamps its answers with its own `capture_identity`. It carries the
host name:

```bash
curl -fsS "http://192.0.2.40:8080/v1/stats" $H | jq '.capture_identity'
# { "node": "relay-a", "instance": "1f4a…", "dialog_generation": 412, … }
```

When you collect replies from several hosts, read `capture_identity.node` to
tell which host gave each one.

### What a multi-node deployment does not do

sipnab does **not** aggregate across nodes. There is:

- no cluster mode,
- no central index,
- no node that answers for another.

Each instance answers for what it captured. You, or an agent holding several
endpoints, perform the correlation above.

## Set it up

### If rtpengine already reports to Homer

Nothing to configure. Capture on the relay host, and sipnab decodes the
control plane it sees:

```sh
sudo sipnab -d eth0
```

Confirm rtpengine is mirroring the control plane and not only RTCP stats:

```sh
grep -E '^homer' /etc/rtpengine/rtpengine.conf
```

You want `homer-enable-ng = true` in that output. Without it, rtpengine sends
RTCP statistics only. Those carry no Call-ID and no SDP.

### If it reports nowhere yet

Add these to the `[rtpengine]` section of `/etc/rtpengine/rtpengine.conf`:

```ini
homer = 192.0.2.60:9060
homer-protocol = udp
homer-id = 2001
homer-enable-ng = true
```

Then restart it:

```sh
sudo systemctl restart ngcp-rtpengine-daemon
```

That is the unit name when you build rtpengine's packages from its own source
tree, as [Add rtpengine to your voice stack](rtpengine-relay.md) does. Debian's
and Ubuntu's own `rtpengine-daemon` package names the unit `rtpengine`
instead.

`homer-id` becomes the per-node key when you correlate several nodes. So give
each relay a distinct one.

## Verify it works

Place one call through the relay, then check that sipnab saw control traffic:

```sh
sudo sipnab -N -d eth0 --report
```

A working setup names the call under **Calls named by a media relay**. If it
does not, work down this list:

| Symptom | Cause | Fix |
|---|---|---|
| No relay-named calls, streams still orphaned | rtpengine sends RTCP stats only | Set `homer-enable-ng = true` and restart |
| Nothing at all on the wire | rtpengine has no `homer` destination | Set one |
| Configured, but still nothing on the wire | The destination refuses the datagrams | See below |
| Control traffic visible, streams still orphaned | Capture missed the HEP, or a filter excluded it | Widen the filter. A filter of your own must admit the relay's media ports |
| Control traffic visible and in the filter, still orphaned | The mirror goes to a UDP port other than 9060, or the build has no `hep` feature | Mirror to port 9060, or use a build that lists `hep` in `sipnab --version`. See [How much a `media-relay` assertion is worth](#how-much-a-media-relay-assertion-is-worth) |
| Relay-named calls appear but media does not | The media is on ports your filter drops | Include the `port-min`–`port-max` range |

### Use `--hep-parse` on a relay capture

`--hep-parse` unwraps HEP datagrams so that the SIP inside them reaches the
parser. It does not stop sipnab reading a mirrored control plane. A relay
capture names the same call with the flag on:

```sh
sipnab -N -I tests/fixtures/rtpengine-ng-hep.pcap --hep-parse --report
```

```text
Calls named by a media relay (no SIP for them in this capture):
Call-ID                                                      Streams
---------------------------------------------------------------------
km-670bd208@sipnab                                           4
```

The UDP port 9060 rule applies with or without the flag. See
[How much a `media-relay` assertion is worth](#how-much-a-media-relay-assertion-is-worth).

### Give the Homer destination a listener

rtpengine connects its Homer socket. A destination that answers with ICMP
port-unreachable makes it drop the socket and log this:

```text
ERR: [core] Connection error from Homer at 192.0.2.1:9060: Connection refused
```

rtpengine then sends no copy, and sipnab has no control plane to read.

- rtpengine 26.3 (the build
  [Add rtpengine to your voice stack](rtpengine-relay.md) makes) reconnects at
  the next call.
- While nothing listens, it logs `Write error to Homer at
  192.0.2.1:9060: Connection refused` for each call it tries to mirror.

So point `--homer` at an address where something receives UDP:

- In production, your Homer collector.
- In a test without a collector, any UDP sink. The repository ships one in
  `harness/hep-sink`.

## Name a call that was already up when you started

Everything above reads the control plane off the wire. So it names the calls
whose `offer` crossed that wire while sipnab was running.

Incident response rarely starts that way.

- You attach to a relay because something is wrong now.
- The calls you care about went up minutes or hours ago.
- Their `offer` happened in the past. No capture can recover it.
- Their media lands in the orphan list.

`--rtpengine-control` closes that gap by asking the relay. Give it the
address rtpengine's ng control socket listens on, its `listen-ng` value.
Same host first:

```sh
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --report
```

A relay on its own host answers the same question over the network:

```sh
sudo sipnab -N -d eth0 --rtpengine-control 192.0.2.40:22222 --report
```

`-N` earns its place in both.

- sipnab writes these summaries as log lines on stderr.
- The TUI silences logs to keep the alternate screen intact.

sipnab asks at two moments and no others:

- once at startup, before the capture opens,
- again when a stream turns up that nothing else explains.

Nothing else polls the relay unless you ask. To have sipnab poll the relay's
statistics on a timer for as long as the capture runs, name the interval:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats-interval 30
```

### What you see when it works

The startup question happens before the first packet. So its answer comes
first. Against rtpengine 12.5.1:

```text
rtpengine at 127.0.0.1:22222: 2 call(s) enumerated, complete; queried 2 of them, 8 relay port(s) now attributable
```

Read it in three parts:

- **Enumerated, complete** means the relay listed everything it held, rather
  than capping the answer.
- **Queried 2 of them** is one `query` per call. `query` is the command that
  says which relay-side port belongs to which call.
- **8 relay ports now attributable** is the index sipnab keeps for the rest of
  the run.
  - Media on any of those eight sockets takes its Call-ID from memory.
  - It costs the relay nothing further.

Streams the relay accounts for stop orphaning. Some calls' own signaling never
appears in the capture. That is the whole reason for asking. Such a call lands
under **Calls named by a media relay**, the same heading the mirrored control
plane fills.

#### Telling a relay's answer from a party's

Every stream says who named its dialog, on every door:

| Value | Who said it | What the address is |
|-------|-------------|---------------------|
| `signaled` | a negotiating party, in its own SDP | that party's endpoint |
| `media-relay` | rtpengine, about a port it allocated | the leg's **midpoint** |

- `GET /v1/streams` and `GET /v1/streams/{id}` carry it as
  `dialog_assertion`.
- The MCP `rtp_stats` tool carries the same key with the same two spellings.
- The TUI's stream detail prints `(via media-relay)` beside the Call-ID.

The value changes what the address means:

- A relay's answer is **not an endpoint**. It names the box the media passed
  through, not where either party sits.
- When you trace a one-way-audio fault to `192.0.2.40:38664`, check the
  value first: `signaled` points at the far end, `media-relay` at the relay
  in the middle.

A `media-relay` assertion is only as trustworthy as the path it arrived on.
Read the next section before you act on one.

An absent key means nobody recorded who asserted the binding. It does not mean
`signaled`.

#### How much a `media-relay` assertion is worth

Two paths deliver it, and they are worth different amounts.

| Path | What sipnab knows about the sender |
|---|---|
| **Delivered** — `--hep-listen`, rtpengine points at sipnab | Whatever you configured: `--hep-allow` restricts the source addresses, `--hep-auth` requires a shared secret, and `--hep-auth-mode hmac` requires a per-message token that covers the addresses the packet asserts |
| **Sniffed** — sipnab reads the mirror on its way to another collector | **Nothing.** No authentication of any kind is possible: the datagram never reaches a sipnab socket, and anything able to transmit on the captured segment can produce one |

Nothing authenticates a sniffed assertion. It carries:

- a Call-ID copied verbatim out of the HEP correlation-id chunk,
- a media address copied out of the SDP.

So a forged datagram can name a call of the sender's choosing. It can bind it
to a socket of the sender's choosing.

sipnab therefore believes a sniffed mirror **only on UDP port 9060**, the HEP
port.

- That narrows the input. It authenticates nobody.
- It stops every datagram on the segment being a candidate.
- It stops nothing sent to 9060.
- sipnab logs one refusal, naming the port it saw.
- The rule is the same with `--hep-parse` on.
  - The flag unwraps the datagram before sipnab reads it.
  - sipnab still believes the mirror inside only if the datagram went to port
    9060.

`--hep-allow` does **not** reach this path. It guards the `--hep-listen`
socket, and there is no socket here.

If any of that matters for your estate, take the delivered path and
authenticate it:

```sh
sudo sipnab -N -d eth0 --hep-listen 0.0.0.0:9060 \
    --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac
```

Then point rtpengine's `homer =` at sipnab.

- It costs you the Homer collector. rtpengine takes exactly one destination.
- That is the trade the table at the top of this page is about.

If your collector sits on a port other than 9060, sipnab does not read the
sniffed copy at all.

`dialog_assertion` is a different question from `dialog_origin`. That second
key says which **capture source** delivered the assertion.

- A relay can name a stream over a HEP mirror, or answer sipnab directly.
- A party's SDP can arrive off the NIC.

The two keys answer one half of that each.

The second summary arrives when the capture ends:

```text
rtpengine at 127.0.0.1:22222: 2 unexplained stream(s) offered, 0 attributed, 4 control transaction(s) spent of a ceiling of 66
```

- The capture path handed two streams to the asking thread.
- Neither of them gained a Call-ID.
- The run spent four control transactions of the 66 it may spend.

A count of zero with no reason line beside it is not a failure. The relay
answered and holds neither port, so that media belongs to something else on
the host.

### What it refuses

Reading a file, sipnab refuses to ask, and says why:

```sh
sipnab -N -I capture.pcap --rtpengine-control 127.0.0.1:22222
```

sipnab prints this warning on stderr before it opens the file:

```text
WARN sipnab::app::bootstrap: --rtpengine-control 127.0.0.1:22222 asks a live relay which calls are up right now, but this run is reading a capture FILE — offline analysis never transmits. The calls in a file ended in the past; the relay's answer would describe whatever is up TODAY, which is other people's traffic. Passive decoding of any relay control plane already in the capture still runs; capture live with -d <device> to ask.
```

The analysis still runs and exits 0. sipnab skips only the question to the
relay.

sipnab sends a relay two commands only: `list` and `query`. It never sends
`offer`, `answer`, `delete` or `start recording`, the `ng` commands that
change a relay.

Three limits bound the asking, whatever the traffic:

- sipnab asks about each relay-side socket at most once per run.
- A run spends at most 66 control transactions.
- At most 4096 relay-side sockets (2048 streams) wait in the queue for a
  question. sipnab counts the ones it turns away.

When sipnab reaches a limit, the end-of-run summary says so. The asking runs on
its own thread, so a relay that does not answer does not slow the capture.

### Read a run that attributed nothing

"Nothing came back" has five meanings, and the summary names which one
applies:

- **The relay did not answer, or refused the question.** sipnab knows
  nothing about the port.
- **The relay named calls sipnab could not read.** The port may belong to
  one of those.
- **The relay capped its own enumeration.** The list came back partial. So
  the port may belong to a call the relay never named. sipnab does not accept
  that quietly:
  - A capped first answer earns one wider ask, for up to 1024 Call-IDs.
  - The summary says whether that wider ask landed or failed.
- **The run spent its transaction ceiling.** sipnab never asked about the
  port at all.
- **The relay does not hold the port.** This one, and only this one, says
  something about the relay: the stream is not its media.

The first four are gaps in what sipnab learned. Only the fifth says the stream
is not the relay's media.

## Relay statistics

Attribution answers whose media a stream is. A relay also keeps counters about
itself:

- the packets it relayed,
- the sessions it holds,
- its own loss and jitter.

`--relay-stats` asks the relay named by `--rtpengine-control` for them, and
prints them:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats
```

Every figure names the relay as its source.

- The header marks it `relay_reported`.
- That is a claim the relay makes about itself, not a measurement sipnab took
  from the wire.

To watch a counter move rather than reading one snapshot, poll on a timer:

```bash
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats-interval 5
```

Each reading marks itself `polled` and names the interval. So it reads as a
timer's output rather than a one-shot answer.

### Three numbers for one call, and none of them wins

One call carries three different "loss" figures. Each one describes a
different socket at a different point on the path:

- **The relay's own count** (`relay_reported`).
  - This is what the relay counted on its own sockets since its last restart.
  - `--relay-compare` puts it beside sipnab's own count for one call. It labels
    each, and prints a one-word verdict with a note.
- **What sipnab saw on the wire** (`sipnab_measured`).
  - These are gaps in the RTP sequence numbers that reached the capture point.
  - So it reflects only what the capture caught.
- **What the far end claims** (`endpoint_reported`).
  - This is the remote endpoint's own assertion over RTCP.
  - Nobody can check it.

sipnab never subtracts one tier from another.

- The relay's count minus sipnab's is not "packets sipnab missed".
- The two count different sockets over different windows. So their difference
  describes nothing.
- Name the tier when you quote the number: "the relay reports 40 lost, our
  capture measured 3 gaps".

The cookbook works each question end to end.
[The relay-statistics recipes](examples.md#ask-a-relay-whether-it-is-dropping-packets)
cover:

- whether a relay drops packets (recipe "Ask a relay whether it is dropping packets"),
- whether it holds sessions nobody released (recipe "Ask a relay what it is still holding"),
- whether its view of one call matches yours (recipe "Compare a relay's per-call count with your capture"),
- this three-tier loss comparison (recipe "Read a relay's loss beside the loss you measured").

### Asking transmits, so a file run refuses

`--relay-stats` needs a live source.

- Asking a relay transmits.
- A capture file's addresses belong to third parties and describe the past.
- So on `-I <file>`, sipnab refuses to ask and says why. It does not reach an
  address the file named:

```bash
sipnab -N -I capture.pcap --relay-stats --rtpengine-control 127.0.0.1:22222
```

```text
ERROR sipnab::app::bootstrap: --relay-stats will not ask a relay on a run that reads a file: asking transmits, and a file's addresses are historical and belong to third parties. Ask from a live capture (-d <device>).
```

The rest of the analysis still runs and exits 0.

## Let an agent ask the relay

Everything above is a person at a terminal.

- `query_relay` gives an AI agent the same reach.
- `decode_ng` lets it read a control message it finds in the capture.

`query_relay` transmits, so it is off by default. It needs three things:

- `--mcp-allow-relay-query`,
- `--rtpengine-control <addr:port>`, the only relay it asks. No tool argument
  changes the destination.
- a live source (`-d`). A run reading a capture file never transmits.

Start an MCP server that an agent can use to ask the local relay:

```bash
sudo sipnab --mcp -N -d eth0 --rtpengine-control 127.0.0.1:22222 --mcp-allow-relay-query
```

Without any one of the three, every other tool works and `query_relay`
answers with an error. On a capture file, with the opt-in given:

```bash
sipnab --mcp -N -I tests/fixtures/rtpengine-ng-hep.pcap --rtpengine-control 127.0.0.1:22222 --mcp-allow-relay-query
```

A `tools/call` for `query_relay` returns this JSON-RPC error:

```json
{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"query_relay is not available on this server. It transmits, so it needs three things: --mcp-allow-relay-query to enable it, --rtpengine-control <addr:port> to say which relay to ask, and a live source. A run reading a capture file can obtain no transmit permit, so an analyst opening somebody else's pcap cannot make sipnab talk to the addresses inside it.","data":{"reason":"not_enabled"}}}
```

`decode_ng` needs none of this.

- It reads a control message already in the capture.
- It reports which path delivered it.
- So an agent can tell a message the relay delivered to sipnab from one
  sipnab read off the wire.

## What rtpengine's forwarding mode changes

Nothing. rtpengine forwards media either in userspace or, with `table = N`
and the `xt_RTPENGINE` kernel module, inside netfilter. A capture on the relay
host sees both directions of the media in both modes, so you do not need to
know which mode a relay runs in.

## What this does not do

- **It does not tie the two halves of a B2BUA call together.** A B2BUA gives
  one call two Call-IDs. The control plane names each leg's media and ties
  neither to the other.
- **It does not read DTLS-SRTP media.** rtpengine terminates DTLS and emits no
  key log. So on a WebRTC-facing relay the payload stays unreadable.
- **It does not attribute recording or forking streams.**
  - Those commands create media that belongs to the call without being one of
    its two legs.
  - Counting one as an ordinary leg would turn a two-party call into a
    three-stream one.
  - sipnab counts them and says so instead. `--report` prints
    **Media-creating relay commands seen** with the count, beside the
    relay-named calls.
  - Their media joins the orphaned streams where the capture holds it.
- **It does not name a call that started before the capture did, from the
  wire alone.**
  - A control message that already happened never reaches the wire. So no
    capture can recover it.
  - Give `--rtpengine-control`, and sipnab asks the relay instead. That closes
    the gap on a live run.
  - Their media stays in the orphan list in two cases: without the flag, or
    on an `-I <file>` run where sipnab refuses to ask.

## See also

- [Encapsulations](encapsulations.md) — HEP and the other wrappers sipnab reads
- [Capture SIP over TLS](tls-capture.md) — when encryption hides the signaling
- [MCP tools](mcp-tools.md) — the agent-facing surface over these results
