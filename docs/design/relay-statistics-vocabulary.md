# The statistics vocabulary (ST-S1)

One vocabulary for every number sipnab reports about media, and the rule that
keeps three incompatible kinds of number from being added together.

This document gates ST1 and everything after it. It is written against the
relays in [`docs/design/relay-statistics-inventory.md`](relay-statistics-inventory.md),
whose observed replies are quoted here rather than recalled.

## Why a vocabulary and not just a schema

A statistics surface is where an operator brings a question like "is the relay
losing my audio". Three different things in this program can answer it, and
they disagree for good reasons:

- rtpproxy reports `rtpa_nlost` for a session.
- sipnab counts sequence-number gaps in the RTP it saw.
- The far endpoint asserts a `fraction lost` in its RTCP receiver report.

All three are "packet loss". None of them measures the same thing. A surface
that showed one of them under a bare heading would be picking a winner without
saying so, and a surface that summed them would produce a number describing
nothing while looking authoritative.

## The three tiers

Every statistic sipnab publishes carries exactly one of these. There is no
fourth, and no value is ever published without one.

### `relay_reported`

What rtpengine or rtpproxy says about ITSELF, obtained by asking it.

**Can be asked:** what the relay has counted since it started, what it is doing
now, and what it holds for one call. It cannot be wrong about which port it
opened or how many datagrams it forwarded through its own socket.

**Cannot be asked:** anything about traffic that did not pass through it, and
anything about a period before its last restart. A relay's counters reset on
restart with nothing in the reply saying so, which is why `uptime` travels
beside them and belongs in any rendering of them.

**Trust:** a claim from a box. rtpengine's control plane is encapsulated and can
carry authentication; rtpproxy's is a bare datagram carrying no credential at
all. That difference already travels with an endpoint attribution and travels
with a statistic for the same reason.

### `sipnab_measured`

Computed from packets sipnab actually saw.

**Can be asked:** anything derivable from the bytes at the capture point —
sequence gaps, interarrival jitter, codec, SSRC changes, the MOS estimate built
on those.

**Cannot be asked:** what happened where sipnab was not looking. A capture on a
mirror port that dropped frames under load undercounts, and the undercount is
indistinguishable from real loss without the capture-path counters that
`capture_health` already publishes. Bounded by what reached the capture point,
which is not the same as what happened.

### `endpoint_reported`

What a remote endpoint asserted, in an RTCP SR, RR or XR.

**Can be asked:** what the far end believes about the stream it received —
`fraction lost`, cumulative loss, its own jitter estimate, and on an XR its own
R-factor, MOS-LQ, MOS-CQ, burst and gap durations and round trip.

**Cannot be asked:** to be checked. It is an assertion by a device sipnab does
not control, arriving inside a packet anyone on the path could have shaped. It
is evidence about what the far end *claims*, never a measurement.

**This tier already exists in the tree** under exactly this name, which is why
it keeps it. `RemoteReceptionReport` and `RemoteVoipMetrics` are filed beside
sipnab's own numbers rather than into them, and `process_rtcp` has never fed
one to the MOS.

## The naming rule, and the inconsistency it inherits

Tier names are `snake_case` on the wire, spelled once in Rust and mapped by a
single `as_wire_str`, the way `RttSource` already is. Two surfaces each keeping
their own map is how a renamed variant ships two spellings of one fact to
consumers that are supposed to agree.

The tree currently publishes provenance in two styles: `endpoint_reported` with
an underscore, and `EndpointAssertion`'s `signaled` and `media-relay` with a
hyphen. **The tier vocabulary uses underscores**, matching `endpoint_reported`
and `xr_voip_metrics` and `sender_report_echo`, which are the names a consumer
already parses. `media-relay` is not renamed by this document — it is a
different field answering a different question, and renaming a shipped wire
value to tidy a convention costs every consumer a migration for no gain to
them. Recorded here so the next reader knows the hyphen is inherited rather
than a decision being repeated.

## Aggregates: what is legal and what is forbidden

**Forbidden without exception:** any arithmetic combining two tiers. No sum, no
difference, no ratio, no average. A relay's packet count minus sipnab's packet
count is not "packets sipnab missed", because the two count different sockets
over different windows with different start times.

**Legal within one tier**, and only when the operands come from one source:

| Aggregate | Legal? | Why |
|---|:--:|---|
| Sum of two rtpproxy global counters from one relay | yes | One counter set, one clock, one restart epoch |
| Sum of the same counter across two relays | **no** | Two restart epochs; one may have restarted mid-window |
| `nrelayed` against `npkts_ina + npkts_ino` on one session | yes | One session, one counter set; the identity held on both live calls sampled, so a mismatch is worth surfacing. Observed, not read from a specification |
| rtpengine `currentstatistics` + `totalstatistics` session counts | **no** | They count at different moments: a session still up is in the first and not yet in the second |
| sipnab's loss beside the endpoint's `fraction lost` | **display only** | Shown adjacent, labeled by tier, never combined into one figure |

The third row is the only cross-check this document blesses, and it is a
comparison rather than an aggregate: it produces a verdict, not a number.

**Where a comparison across tiers is the operator's actual question** — "does
the relay's view of this call match mine" — the answer is a comparison with
both inputs shown and both tiers named. Never a single reconciled figure.

## Missing is not zero

This is the rule most likely to be broken by an ordinary-looking edit, so it is
stated for the wire and for prose separately.

**On the wire:** a statistic that was not obtained is **absent**, not null and
not zero. JSON surfaces omit the key, the way `Option` fields already serialize
with `skip_serializing_if = "Option::is_none"`. A caller that does not find a
key knows nothing was learned; a caller that finds `0` knows the relay counted
zero.

These are three different facts and must stay three:

| State | Wire | Means |
|---|---|---|
| Counted, and the count is zero | `"npkts_discard": 0` | The relay dropped no packets |
| Not asked for | key absent | Nobody requested it |
| Asked for and refused | key absent, plus an entry in the reply's refusals naming the statistic and the code | The relay was asked and said no |

The third must never collapse into the second. rtpproxy's refusal codes mean
different things — `E68` no such statistic in this build, `E62` no such
per-session counter, `E50` no session with those tags — and an operator told
"unavailable" cannot tell a misspelling from a missing call.

**In prose:** an absent value renders as `—` or as the word `unavailable` with
the reason beside it, never as `0`, never as a blank cell that a reader will
read as zero. The precedent is `mos_grounding: unpublished` and
`round_trip_note`, both of which exist so a figure nobody measured does not
pass as a pass.

## The rendering rule every surface follows

One number, one reading, on all four surfaces. Per statistic, every surface
renders:

1. **The relay's own name for it**, unaltered. `npkts_relayed`, not
   `packets_relayed` and not `Packets Relayed`. The key set is version-specific
   and translating it invents a vocabulary that has to be maintained against
   every future release.
2. **The value as the source gave it.** rtpengine delivers whole numbers as
   bencode integers AND as strings — `uptime` is `"134"` beside dozens of
   integers. Both render as the digits they are; neither is coerced, because a
   coercion that succeeds silently on one version fails silently on the next.
3. **The tier**, from the vocabulary above.
4. **When it was obtained**, because a relay-reported figure is as old as the
   moment it was asked for, and an operator comparing it to a live capture
   needs to know the gap.
5. **What it is NOT.** Only where a name invites the wrong reading: rtpproxy's
   `npkts_rcvd` is packets the RELAY received, not packets the call carried,
   and a stream the relay never anchored contributes nothing to it.

A surface may lay these out differently — a TUI column, a JSON field, a CLI
table — but none may omit 1, 2 or 3. A number without its tier is the failure
this document exists to prevent.

## What ST-S1 hands to ST-S3

The surface contract owes, per capability: the CLI spelling, the REST route and
payload, the MCP tool name and schema, the TUI affordance, and a statement of
which of the five rendering elements each surface carries where. A surface that
deliberately omits one says so and says why.

## What this does not settle

- Polling. ST4 owns whether and how a timer may re-ask, and this document says
  only that element 4 of the rendering rule — when it was obtained — is what
  makes a polled figure distinguishable from a freshly asked one.
- Which specific statistics each surface exposes by default. ST2 and ST3 own
  the inventories; this owns the rule they are rendered under.
