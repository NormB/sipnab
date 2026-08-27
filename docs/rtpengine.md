# Attribute media on an rtpengine relay

You installed sipnab on a media relay, ran a capture, and got a screen full of
orphaned RTP streams. Every packet is there and none of it says which call it
belongs to. This page fixes that.

**The short version.** A standalone relay carries no SIP, so a capture there
has media and nothing to name it with. rtpengine knows the name — its `ng`
control protocol carries the Call-ID and the ports it allocated — and it can
already mirror that control plane to a Homer collector. sipnab reads that
mirror and ties the media to the call. A call that was already up when the
capture opened left no control message for the mirror to carry, so
`--rtpengine-control` asks the relay for that one directly.

## The problem, on a real capture

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

With it, the same media resolves to one call — and gains a codec, because the
control plane carries the SDP too:

```text
RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts
----------------------------------------------------------------------------------
0x0a0a0a0a   0    PCMU     8000   192.0.2.60:40001      192.0.2.40:38156      10
0x0b0b0b0b   0    PCMU     8000   192.0.2.60:40002      192.0.2.40:38664      10
0x0a0a0a0a   0    PCMU     8000   192.0.2.40:38664      192.0.2.60:40002      10
0x0b0b0b0b   0    PCMU     8000   192.0.2.40:38156      192.0.2.60:40001      10

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

Four streams and not two: the relay holds its own socket per leg, plus the far
party's on the other side of each. All four belong to one call.

## Which method fits your deployment?

Read down the first column and stop at the first row you can satisfy.

| Your situation | Use | Changes rtpengine? | Notes |
|---|---|---|---|
| rtpengine already reports to a Homer collector | Capture on the relay host | **No** | sipnab reads the copy already on the wire. Nothing about your Homer pipeline changes. |
| rtpengine reports nowhere yet | Turn on `--homer-enable-ng`, point it anywhere sipnab can see | Yes, once | The destination can be a collector, or a host that discards the traffic |
| You need it delivered rather than sniffed | `--hep-listen` on sipnab, point rtpengine at it | Yes | Costs you the collector — see the warning below. Requires 0.5.125 or later: earlier builds accepted the traffic and decoded none of it |

Every row here covers control messages that cross the wire while sipnab
runs. None of them reaches a call the relay set up before the capture
opened. For that, add `--rtpengine-control`, which asks the relay and runs
alongside whichever row you picked.

**rtpengine takes exactly one Homer destination.** `--homer` is a single
value, not a repeatable option, so "send to the real collector and to sipnab"
does not exist. Anything that points rtpengine at sipnab takes it away from
the collector it feeds. That is why sipnab reads the traffic off the wire by
default: a diagnostic tool has no business in a production data path, and if
sipnab stops, nothing else notices.

## Several rtpengine instances behind one proxy

A proxy that load-balances across a pool of relays puts each call on exactly
one of them. Run **one sipnab per host**: the proxy's sees the SIP, each
relay's sees the media its own host relays.

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
# On relay-a, relay-b, relay-c — identical, and each asks only its own relay.
# The API binds to the host's own address, not loopback: the whole point of the
# procedure below is that ANOTHER machine queries this one. A non-loopback bind
# is refused without authentication, which is why --api-key is not optional
# here.
sudo sipnab -d eth0 --rtpengine-control 127.0.0.1:22222 \
  --api 0.0.0.0:8080 --api-key "$SIPNAB_API_KEY"
```

The queries below need the address, the key and a Call-ID. Set them once, on
whichever machine you are running `curl` from:

`$H` interpolates `$KEY`, so set the key first — an `$H` built before `$KEY`
exists carries an `Authorization` header with no token in it, and every query
below then returns `401`.

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

`--rtpengine-control` takes one address, and in this topology that is correct
rather than a limitation: a relay can only answer for calls it is carrying, so
a sipnab asking a relay on another host would get `RelayDoesNotHoldIt` for
everything.

### Finding a call without asking every relay

The naive procedure is a broadcast: ask all ten relays, discard nine misses.
You do not have to. **The proxy's own SDP names the relay**, because the `c=`
address the proxy negotiated IS the rtpengine it steered the call to.

**Step 1 — ask the proxy which relay has it.**

```bash
curl -fsS "http://proxy:8080/v1/dialogs/$CALL_ID" $H \
  | jq -r '.sdp_timeline[0] | "\(.media_addr):\(.media_port)"'
# 192.0.2.40:38664
```

**Step 2 — ask that one relay, and no others.**

```bash
curl -fsS "http://192.0.2.40:8080/v1/dialogs/$CALL_ID" $H | jq '.streams'
```

A relay that never carried the call answers **404**, not an empty success.
That distinction is load-bearing: "I do not have this call" and "this call had
no media" are different findings, and a relay that answered `200` with an
empty list would report the second when it meant the first.

### Knowing whose answer you are holding

Every node stamps its answers with its own `capture_identity`, which carries
the host name:

```bash
curl -fsS "http://192.0.2.40:8080/v1/stats" $H | jq '.capture_identity'
# { "node": "relay-a", "instance": "1f4a…", "dialog_generation": 412, … }
```

Collecting replies from several hosts, that field is what keeps them
attributable to the host that gave them. Without it, two JSON documents from
two relays are indistinguishable once they are side by side in a terminal.

### What a multi-node deployment does not do

sipnab does **not** aggregate across nodes. There is no cluster mode, no
central index, and no node that answers for another. Each instance answers for
what it captured, and the correlation above is something you (or an agent
holding several endpoints) perform. That is a deliberate limit, not a missing
feature: an aggregator is infrastructure, and
[positioning](design/positioning.md) rules it out.

[`tests/multi_node_relay_fanout_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/multi_node_relay_fanout_test.rs) pins the three properties this
procedure rests on — the proxy holds signaling and no media, exactly one relay
claims a call, and the proxy's SDP names which one.

## Set it up

### If rtpengine already reports to Homer

Nothing to configure. Capture on the relay host and sipnab decodes the
control plane it sees:

```sh
sudo sipnab -d eth0
```

Confirm rtpengine is mirroring the control plane and not only RTCP stats:

```sh
grep -E '^homer' /etc/rtpengine/rtpengine.conf
```

You want `homer-enable-ng = true` in that output. Without it rtpengine sends
RTCP statistics only, which carry no Call-ID and no SDP.

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
sudo systemctl restart rtpengine
```

`homer-id` becomes the per-node key when you correlate several nodes, so give
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
| Control traffic visible, streams still orphaned | Capture missed the HEP, or a filter excluded it | Widen the filter; the default filter excludes media |
| Control traffic visible and in the filter, still orphaned | `--hep-parse` on a build before 0.5.128 | Leave `--hep-parse` off, or upgrade. See below |
| Relay-named calls appear but media does not | The media is on ports your filter drops | Include the `port-min`–`port-max` range |

### `--hep-parse` is for HEP-encapsulated SIP, not for this

`--hep-parse` unwraps a HEP datagram and hands the payload inside it to the
parser. That is what you want when a collector feeds you SIP over HEP, and
until 0.5.128 it quietly switched this feature off.

sipnab spots mirrored `ng` two ways: by the metadata a HEP listener recorded
before stripping the wrapper, or by parsing the wrapper off a sniffed datagram
that still has one. Unwrapping used to discard the wrapper without recording
what it said, so neither route had anything left to match on. The control plane
reached the capture and went straight in the bin, no counter moved, and every
relay stream stayed orphaned.

Nothing reported it, and that is the part worth remembering: the build carried
the feature, the filter carried the ports, and the datagrams sat plainly on the
wire. Every setting was correct and the answer was still empty.

From 0.5.128 the unwrap carries the wrapper's capture protocol and correlation
id forward, so the two features coexist and the flag is safe to leave on. On an
older build, turn it off for a relay capture.

### The destination has to accept the traffic

rtpengine CONNECTS its Homer socket, so a destination that answers with ICMP
port-unreachable makes it give up and log this:

```text
ERR: [core] Connection error from Homer at 192.0.2.1:9060: Connection refused
```

After that it sends nothing, which looks exactly like the feature not working.
Pointing `--homer` at an address nobody listens on is therefore not a way to
"just put it on the wire" — something has to absorb it.

In the deployment this targets, that something is your real Homer collector,
which is already there. If you are testing without one, run any UDP sink at
the address. The harness ships one for exactly this reason — see
`harness/hep-sink`.

## Name a call that was already up when you started

Everything above reads the control plane off the wire, so it names the calls
whose `offer` crossed that wire while sipnab was running. Incident response
rarely starts that way. You attach to a relay because something is wrong
now, and the calls you care about went up minutes or hours ago — their
`offer` happened in the past, no capture can recover it, and their media
lands in the orphan list.

`--rtpengine-control` closes that gap by asking the relay. Give it the
address rtpengine's ng control socket listens on — its `listen-ng` value.
Same host first:

```sh
sudo sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --report
```

A relay on its own host answers the same question over the network:

```sh
sudo sipnab -N -d eth0 --rtpengine-control 192.0.2.40:22222 --report
```

`-N` earns its place in both. sipnab writes these summaries as log lines on
stderr, and the TUI silences logs to keep the alternate screen intact.

sipnab asks at two moments and no others: once at startup, before the
capture opens, and again when a stream turns up that nothing else explains.
There is no interval flag because there is no timer. A tool that talks to a
production relay on a schedule is a service, and this is a diagnostic.

### What you see when it works

The startup question happens before the first packet, so its answer comes
first. Against rtpengine 12.5.1:

```text
rtpengine at 127.0.0.1:22222: 2 call(s) enumerated, complete; queried 2 of them, 8 relay port(s) now attributable
```

Read it in three parts. **Enumerated, complete** means the relay listed
everything it held rather than capping the answer. **Queried 2 of them** is
one `query` per call, which is the only command that says which relay-side
port belongs to which call. **8 relay ports now attributable** is the index
sipnab keeps for the rest of the run: media on any of those eight sockets
takes its Call-ID from memory and costs the relay nothing further.

Streams the relay accounts for stop orphaning. A call whose own signaling
never appears in the capture — the whole reason for asking — lands under
**Calls named by a media relay**, the same heading the mirrored control
plane fills.

#### Telling a relay's answer from a party's

Every stream says who named its dialog, on every door:

| Value | Who said it | What the address is |
|-------|-------------|---------------------|
| `signaled` | a negotiating party, in its own SDP | that party's endpoint |
| `media-relay` | rtpengine, about a port it allocated | the leg's **midpoint** |

`GET /v1/streams` and `GET /v1/streams/{id}` carry it as `dialog_assertion`,
the MCP `rtp_stats` tool carries the same key with the same two spellings, and
the TUI's stream detail prints `(via media-relay)` beside the Call-ID.

The distinction changes what the address means, which is why it is not folded
away. A relay's answer is **authoritative about the port** — rtpengine cannot
be wrong about which socket it opened — and at the same time it is **not an
endpoint**: it names the box the media passed through, not where either party
sits. An operator tracing a one-way-audio fault to `192.0.2.40:38664` needs to
know whether that is the far end or the box in the middle, and those lead to
opposite next steps.

An absent key means nobody recorded who asserted the binding. It does not mean
`signaled` — that is a claim, and keeping the two apart is the entire reason
the field exists.

`dialog_assertion` is a different question from `dialog_origin`, which says
which **capture source** delivered the assertion. A relay can name a stream over a
HEP mirror or answer sipnab directly, and a party's SDP can arrive off the NIC.
The two keys answer one half of that each.

The second summary arrives when the capture ends:

```text
rtpengine at 127.0.0.1:22222: 2 unexplained stream(s) offered, 0 attributed, 4 control transaction(s) spent of a ceiling of 66
```

The capture path handed two streams to the asking thread, neither of them
gained a Call-ID, and the run spent four control transactions of the 66 it
may spend. A count of zero with no reason line beside it is the honest
answer rather than a failure: the relay answered and holds neither port, so
that media belongs to something else on the host.

### What it refuses

Reading a file, sipnab refuses to ask, and says why:

```sh
sipnab -N -I capture.pcap --rtpengine-control 127.0.0.1:22222
```

```text
--rtpengine-control 127.0.0.1:22222 asks a live relay which calls are up
right now, but this run is reading a capture FILE — offline analysis never
transmits. The calls in a file ended in the past; the relay's answer would
describe whatever is up TODAY, which is other people's traffic. Passive
decoding of any relay control plane already in the capture still runs;
capture live with -d <device> to ask.
```

The analysis still runs and still exits 0. What the run loses is the ask,
and it says so before the capture opens rather than looking like a run that
asked and learned nothing.

The two questions sipnab can put to a relay are `list` and `query`, and
that is a property of the type reaching the relay rather than a convention.
ng also carries `offer`, `answer`, `delete` and `start recording`, each of
which changes a production relay. None of them has a representation on this
path, so no call site reaches one by accident.

Three bounds hold the asking down, and none of them grows with how much
traffic the capture carries:

- sipnab asks about each relay-side socket at most once for the whole run,
  so a stream that stays unexplained does not re-ask on every packet.
- A per-run ceiling caps control transactions at 66 — one `list` plus a
  `query` per call at rtpengine's own list limit of 32, twice over. Enough
  for a full startup snapshot and one comparable refresh, and no more.
- The queue handing sockets from the capture path to the asking thread is
  bounded, so a slow relay cannot grow it.

When a bound bites, sipnab counts it and says so. The asking runs on its
own thread, so the packet path offers a socket and moves on rather than
waiting out a round trip to a relay that may be down.

### Read a run that attributed nothing

"Nothing came back" has five meanings, and sipnab keeps them apart rather
than collapsing them into one shrug:

- **The relay did not answer, or refused the question.** sipnab knows
  nothing about the port.
- **The relay named calls sipnab could not read.** The port may belong to
  one of those.
- **The relay capped its own enumeration.** The list came back partial, so
  the port may belong to a call the relay never named.
- **The run spent its transaction ceiling.** sipnab never asked about the
  port at all.
- **The relay does not hold the port.** This one, and only this one, says
  something about the relay: the stream is not its media.

The first four are gaps in what sipnab learned. Reporting any of them as
the fifth would turn a run that never reached the relay into a run that
asked and heard the stream belongs to nobody.

## What rtpengine's forwarding mode changes

Nothing, and a measurement says so rather than an assumption.

rtpengine forwards either in userspace or, with `table = N` and the
`xt_RTPENGINE` kernel module, inside netfilter. If kernel-forwarded media were
invisible to a capture, attributing it would be pointless — so this run
checked it against rtpengine 12.5.1, with the module confirmed active and
accounting the packets itself:

```text
/proc/rtpengine/0/list   local 192.0.2.40:34232  250 packets   [kernel-forwarded]
                         output → 192.0.2.60:40001             250 packets
capture on the relay     ingress 500/500         egress 500/500
```

Both directions stay fully visible in both modes. The reason is structural: a
capture's receive tap runs before netfilter, and the module re-injects through
the normal transmit path, which passes the transmit tap. You do not have to
know or care which mode a relay runs in.

## What this does not do

Stated here rather than discovered later.

- **It does not tie the two halves of a B2BUA call together.** A B2BUA gives
  one call two Call-IDs. The control plane names each leg's media and ties
  neither to the other.
- **It does not read DTLS-SRTP media.** rtpengine terminates DTLS and emits no
  key log, so on a WebRTC-facing relay the payload stays unreadable.
- **It does not attribute recording or forking streams.** Those commands
  create media that belongs to the call without being one of its two legs, and
  counting one as an ordinary leg would turn a two-party call into a
  three-stream one. sipnab counts them and says so instead: `--report`
  prints **Media-creating relay commands seen** with the count, beside the
  relay-named calls, and their media joins the orphaned streams where the
  capture holds it.
- **It does not name a call that started before the capture did, from the
  wire alone.** A control message that already happened never reaches the
  wire, so no capture can recover it. Give `--rtpengine-control` and sipnab
  asks the relay instead, which closes the gap on a live run. Without the
  flag, or on an `-I <file>` run where sipnab refuses to ask, their media
  stays in the orphan list.

## Where this is going: the next phase

**None of this section describes what sipnab does today.** What this page
documents above is one hop naming its own media, proven against a recorded
capture and against a live relay. This section states what that foundation
exists FOR, so the next phase aims at a goal rather than at whatever comes
next.

The goal is a call that crosses an SBC, a proxy, an rtpengine and a PBX,
assembled end to end, so that an operator can ask a question in their own
words and an agent answers with evidence from every hop the call touched.

Naming media on the relay is the hop that was missing, because it is the only
hop that carries no SIP of its own. Once each hop can name a call, an agent
can filter to a customer — by caller, callee, trunk, address, or time window —
and pull the whole call rather than one machine's view of it.

These are the questions that arrive, and what answering each one takes.

| The customer says | The question really is | What the answer needs |
|---|---|---|
| "Our calls sound bad" | Where in the path did the media degrade? | Per-hop loss, jitter and MOS on the SAME call, so a good leg and a bad leg separate cleanly |
| "Calls are not completing" | Which hop rejected it, and what did it say? | The final response and its origin hop, plus whether media was ever negotiated |
| "Calls drop after a while" | Who tore it down, and on what clock? | The BYE or the timeout, and which side sent it |
| "We hear them, they can't hear us" | Which direction is missing, and from where? | Both directions of media at each hop, not just a packet count |
| "It only fails for one carrier" | What is different about that path? | The same call shape across two trunks, compared |

### "Our calls sound bad"

The hard part is not measuring quality, it is locating it. A relay reporting
2% loss tells you nothing on its own — the question is whether the loss was
already there when the media arrived, or appeared on the way out.

That needs the same call measured on both sides of each hop, which needs each
hop to agree on the call's name. On the relay that agreement is what
this page adds. The analysis then reads as a chain: clean into the SBC, clean
into the relay, lossy out of the relay, and now the fault has an address
rather than a symptom.

Watch for the answer being "neither hop": identical loss at every hop points
at the access network, and a codec that changes between hops points at
transcoding rather than at the network.

### "Calls are not completing"

Same filter, different evidence. Here the media is usually absent rather than
degraded, so the question moves to signaling — and to the gap between them.

The failure modes separate cleanly once you can see every hop at once:

- **A final response from an upstream hop**, which names the rejecter. The
  response class matters: a 4xx is the far end declining, a 5xx is a server
  failing, a 6xx is a global refusal, and they lead to different owners.
- **No response at all**, which is a timeout, and the hop that stopped
  answering is the one to look at.
- **A call answered with no media**, which is a negotiation failure rather
  than a routing one — the signaling succeeded and the SDP did not.
- **A relay with no ports left**, which looks like a random failure from the
  proxy's side and is obvious from the relay's.

The last two are exactly the cases a signaling-only view gets wrong, because
from the proxy the call looks answered.

### "Calls drop after a while"

A drop has a clock attached, and the clock identifies the cause. A tear-down
at a round number is a timer — a session timer, a NAT binding, a relay's own
media timeout. A tear-down when media stopped is the media stopping. Reading
the relay's teardown against the proxy's BYE says which came first, which is
the whole question.

### "We hear them, they can't hear us"

One-way audio is a direction problem, and a relay is where directions become
visible: it holds both parties' sockets, so a leg with media arriving and
nothing leaving is plainly asymmetric. The value of naming the call is being
able to say WHICH call is asymmetric on a box carrying hundreds.

### "It only fails for one carrier"

The comparison case. Two calls of the same shape down two trunks, assembled
the same way, differing in one hop's behavior. Hard to do by hand across
machines and straightforward once every hop names its calls the same way.

## See also

- [Encapsulations](encapsulations.md) — HEP and the other wrappers sipnab reads
- [Capture SIP over TLS](tls-capture.md) — when encryption hides the signaling
- [MCP tools](mcp-tools.md) — the agent-facing surface over these results
