# The failure and edge-case catalog (ST-S4)

Enumerated before implementation so each surface's tests are drawn from one
list rather than from whatever its author thought of.

This gates ST9 and the 50-test minimum on every surface. Every row below was
produced against a running relay on 2026-09-12 unless it says otherwise; the
relays and versions are in
[`docs/design/relay-statistics-inventory.md`](relay-statistics-inventory.md).

## How to read the table

**Same five ways on all four surfaces.** Each condition has one classification,
and every surface reports that classification. What differs is layout, never
which condition a caller is told about.

The five classifications:

| Classification | Means | Whose problem |
|---|---|---|
| `not_configured` | sipnab was never given a relay to ask | The operator's invocation |
| `not_permitted` | No transmit permit for this run | The operator's invocation |
| `unreachable` | Asked, nothing came back | The network or the relay |
| `refused` | Asked, the relay said no, and it said why | The request |
| `suspect` | An answer arrived and something about it cannot be trusted | The answer |

`suspect` is the one that did not exist before this catalog. An answer that is
present, well formed and wrong is the failure mode this whole subsystem is most
likely to ship, and folding it into "ok" is how it would ship.

## The catalog

### 1. No relay configured

Nothing was passed to name a relay. Not an error condition — the common case.

**All surfaces:** `not_configured`, naming the flag that would supply one. CLI
exits 0 with the statistics section absent, not empty. REST returns 200 with the
classification, not 404: the route exists, the relay does not. MCP refuses and
names the missing flag, as `query_relay` already does. TUI's `RelayStats` view
opens and says what to start the run with.

### 2. No transmit permit

A file-backed run cannot obtain one at all, which is deliberate: an analyst
opening somebody else's pcap must not be able to make sipnab talk to the
addresses inside it.

**All surfaces:** `not_permitted`, saying that this is a property of the run's
source rather than of the relay. Never retried, never degraded into
`unreachable` — the distinction is the whole safety property.

### 3. Relay unreachable

Observed: both relays time out. **A wrong port and a wrong host are
indistinguishable** — UDP, no ICMP surfaced to the caller.

```
rtpproxy  172.28.0.12:22299 "I"        -> <TIMEOUT>
rtpproxy  172.28.0.99:22223 "I"        -> <TIMEOUT>
rtpengine 172.28.0.11:22299 ping       -> <TIMEOUT>
```

**All surfaces:** `unreachable`, with the address asked and the timeout waited.
Must NOT say "the relay is down": nothing observed distinguishes a down relay
from a filtered port, a wrong port, or a reply that was lost. Saying the weaker
true thing is the requirement.

### 4. Relay refuses, and the reason is not one reason

rtpproxy answers with numeric codes; rtpengine with a structured error and prose.

| Relay | Probe | Reply |
|---|---|---|
| rtpproxy | `G nosuchstat` | `E68` |
| rtpproxy | `Q <call> <tags> nosuchcounter` | `E62` |
| rtpproxy | `Q <call> <wrong tags>` | `E50` |
| rtpproxy | `Qz <call> <tags>` | `E19` |
| rtpproxy | `Q` with nine arguments | `E1` |
| rtpproxy | empty command | `E5` |
| rtpengine | unknown command | `{"result":"error","error-reason":"Unrecognized command"}` |
| rtpengine | `query` with no call-id | `{"result":"error","error-reason":"No call-id in message"}` |
| rtpengine | `query` for a call it does not hold | `{"result":"error","error-reason":"Unknown call-id"}` |
| rtpengine | truncated bencode | `{"result":"error","error-reason":"Could not decode bencode dictionary"}` |

**All surfaces:** `refused`, carrying the relay's own code or reason verbatim
AND what was asked. Collapsing these to "unavailable" tells an operator their
call is missing when the truth is a misspelled statistic name.

`E68` and `E50` in particular must never share a message. One is about the
vocabulary, the other is about their call.

### 5. There is no partial answer from rtpproxy

**The finding that constrains the design.** `G` with several names returns one
value per name — or, if ANY name is unknown, `E68` for the whole request:

```
G nsess_created npkts_rcvd ncmds_rcvd   -> 2 18000 153
G nsess_created nosuchstat              -> E68
G nosuchstat nsess_created              -> E68
```

So a request for all 28 statistics loses all 28 if one name is wrong, and the
reply does not say which one. Two consequences, both binding:

1. **Never ask for a name not known to be answerable.** The set comes from C3
   in [`docs/design/relay-statistics-surfaces.md`](relay-statistics-surfaces.md),
   established by asking, not from a table compiled into sipnab.
2. **A bulk request that returns `E68` is retried name by name**, or it is
   reported as `refused` for the whole set with the set named. It is never
   reported as a partial success, because rtpproxy gave no partial.

rtpengine differs: `statistics` takes no name list, so this condition cannot
arise there. A surface must not present the two as one behavior.

### 6. A restart resets every counter, and rtpproxy does not say so

Measured either side of `docker restart rtpproxy`:

| | Before | After |
|---|---:|---:|
| `sessions created` | 1 | 0 |
| `packets received` | 9000 | 0 |
| `G nsess_created` | 1 | 0 |
| `G npkts_rcvd` | 9000 | 0 |

**rtpproxy publishes no uptime and no start time.** Nothing in any of its
replies distinguishes a relay that has handled nothing from one that restarted
a second ago. rtpengine does publish `totalstatistics/uptime`, so the same
event is detectable there — if something reads it.

**All surfaces:** a cumulative counter is rendered with `uptime` beside it where
the relay publishes one. Where it does not — rtpproxy — the rendering says the
counters are since an unknown start, once, plainly, and not in a footnote. A
polled series that steps backwards is classified `suspect` with "a counter
decreased, which a cumulative counter cannot do; the relay probably restarted",
never smoothed and never reported as a drop in traffic.

### 7. A reused cookie replays a stale reply, on BOTH relays

Both relays cache by cookie and replay on a repeat. A client that reuses one
receives a confidently wrong answer rather than an error:

```
rtpproxy  cookie=deadbeef  "I"          -> sessions created: 2 | …
rtpproxy  cookie=deadbeef  "V"          -> sessions created: 2 | …   (the I reply)
rtpengine cookie=cafef00d  ping         -> {"result":"pong"}
rtpengine cookie=cafef00d  statistics   -> {"result":"pong"}          (the ping reply)
```

This was hit during the ST-S2 inventory: three different questions returned one
`pong` and the reply looked perfectly valid.

**All surfaces:** a fresh cookie per request, never a counter that could restart
with the process. A reply whose cookie does not match the request is discarded
and classified `suspect`, never interpreted — which is the rule the control
decoder already applies to sniffed replies.

### 8. A key present in one version and absent in the next

`rtpa_nlost` is a global statistic on rtpproxy 3.2.0 and returns `E68` on
2.1.1, where the same counter survives only per-session through `Q`.

**All surfaces:** `refused` for that name with the relay's code, beside the
statistics that did answer. Never an empty result for the whole request, and
never a zero. A surface that offers a fixed menu of statistic names is wrong by
construction; the menu comes from the relay.

### 9. Zero, absent, and refused are three states

Restated from ST-S1 because this is where the tests come from.

| State | Wire | A test must distinguish it from |
|---|---|---|
| Counted, zero | key present, value `0` | Both of the others |
| Not asked for | key absent | A refusal |
| Asked, refused | key absent, entry in `refusals` with name and code | A value of zero |

Three tests minimum per surface, not one.

### 10. The tags the relay holds are not the tags on the wire

OpenSIPS keys an rtpproxy session on a `;1` viabranch-suffixed tag. Asking with
the tag the capture saw returns `E50`, and the relay's log says
`tags …/… not found`.

**All surfaces:** a per-call request tries what the relay is likely to hold, and
an `E50` reports WHICH tag spellings were tried. "The relay is not holding this
call" without that list is a claim the evidence does not support. rtpengine keys
tags verbatim, so one rule cannot serve both and neither may be assumed.

### 11. Value overflow

rtpproxy prints counters with `%lu`; rtpengine sends bencode integers and, for
some keys, strings. **Not reproduced** — no relay in reach has run long enough
to wrap a 64-bit counter, and manufacturing one would test a fixture rather
than a relay.

**All surfaces:** the value is carried as the relay sent it and is never parsed
into a narrower type. A value that will not fit the surface's own numeric type
is rendered as the digits received and classified `suspect`, not truncated and
not rejected. Tested against recorded replies with oversized values, and the
test says the wire case is unreachable and why.

### 12. No capture running

Statistics about a relay do not require a capture — the relay is asked
directly. But C4, comparing relay against capture, does.

**All surfaces:** C1, C2 and C3 answer normally. C4 returns `not_configured`
naming the capture, not the relay, so an operator is not sent to debug a relay
that is working.

### 13. A timer fires while a poll is outstanding

CLI only, since polling is CLI-only.

**Behavior:** the second tick is SKIPPED and counted, never queued and never
run concurrently. A relay slower than the interval must not accumulate a
backlog of outstanding transactions against it, which is how a diagnostic tool
becomes a load generator. The skipped count is reported in the run's summary,
because an interval that is silently not being met is a number an operator is
reading wrongly.

## What the 50-test minimum is drawn from

Thirteen conditions above. Per surface, at minimum:

- One test per condition the surface can reach: 13 for the CLI, 12 for REST,
  MCP and the TUI, which have no polling.
- Three for condition 9 rather than one, per its own table.
- Ten for condition 4 rather than one: six rtpproxy codes and four rtpengine
  reasons, none of which may be collapsed into another.
- Two each for conditions 5, 6, 7 and 10 rather than one, because the two
  relays behave differently in every one of them.

**That comes to 28 on the CLI and 27 on each of the other three.** Counted
rather than asserted, and it is below the 50-test minimum on purpose: this
catalog is the FAILURE half. The remaining tests on each surface come from the
success paths in
[`docs/design/relay-statistics-surfaces.md`](relay-statistics-surfaces.md) —
five capabilities, two relays, the three rendering elements no surface may
omit, and the values that must survive uncoerced — plus whatever that surface's
own shape demands.

The point of drawing from one list is not to reach a number. It is that four
surfaces cannot disagree about what a failure looks like if their failure tests
came from the same thirteen rows.
