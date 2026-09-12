# What each relay actually reports (ST-S2)

An inventory taken from running relays, not from their manuals. Every figure
below was read off a live control socket on 2026-09-12 and is quoted as the
relay printed it.

This document gates ST2 and ST3. Nothing that reads a relay's counters is
implemented until the shape below is settled, because the alternative is a
schema decided by whichever call site was written first.

## What was observed, and on what

| Relay | Version | Where | Control socket |
|---|---|---|---|
| rtpengine | 12.5.1.31-1 | harness container `rtpengine` | `172.28.0.11:22222`, ng/bencode |
| rtpproxy | 2.1.1-r3 (Alpine 3.22, aarch64) | harness container `rtpproxy` | `172.28.0.12:22223`, text |
| rtpproxy | 3.2.0.630f75e (built from source) | a separate lab host | its own UDP control port, text |

Two rtpproxy versions on purpose. The key sets differ between them, and a
schema frozen to one is the pinned-value defect this repository has paid for
before.

## The first rule: the binary's string table is not the schema

Both rtpproxy builds carry statistic names in their string tables that the `G`
command refuses. On 2.1.1, `npkts_ina`, `npkts_ino` and `rtpa_nlost` are all in
the table and all answer `E68`. On 3.2.0, nine more do the same:
`npkts_in`, `npkts_discard_idx`, `npkts_relayed_idx`, `npkts_resizer_in_idx`,
`rtpa_javg`, `rtpa_jlast`, `rtpa_jmax`, `rtpa_stats` and `rtpa_stats_jitter`.

They are not global counters. Some are per-session counters reachable through
`Q`; the rest are internal. A tool that built its vocabulary by scraping the
binary would offer a caller a dozen names that answer nothing, and the refusal
is indistinguishable from a typo.

**Ask the relay. Do not infer the vocabulary.**

## rtpproxy: the global counters (`G`)

`G <name> [<name>…]` returns one value per name, space separated, in the order
asked. A name the build does not know returns `E68`, which is also what a
misspelling returns.

Observed values are from the session that took them and are not the point; the
name, the type and the version columns are.

| Name | Type | 2.1.1 | 3.2.0 | What it counts |
|---|---|:--:|:--:|---|
| `nsess_created` | integer | yes | yes | Sessions created since start, cumulative |
| `nsess_destroyed` | integer | yes | yes | Sessions torn down, cumulative |
| `nsess_timeout` | integer | yes | yes | Sessions ended by the TTL rather than by a command |
| `nsess_complete` | integer | yes | yes | Sessions that saw media on both sides |
| `nsess_nortp` | integer | yes | yes | Sessions that saw no RTP at all |
| `nsess_owrtp` | integer | yes | yes | Sessions that saw RTP in one direction only |
| `nsess_nortcp` | integer | yes | yes | Sessions that saw no RTCP |
| `nsess_owrtcp` | integer | yes | yes | Sessions that saw RTCP in one direction only |
| `nplrs_created` | integer | yes | yes | Player instances created |
| `nplrs_destroyed` | integer | yes | yes | Player instances destroyed |
| `npkts_rcvd` | integer | yes | yes | Packets received, cumulative |
| `npkts_played` | integer | yes | yes | Packets emitted by the player |
| `npkts_relayed` | integer | yes | yes | Packets forwarded, cumulative |
| `npkts_resizer_in` | integer | yes | yes | Packets entering the repacketizer |
| `npkts_resizer_out` | integer | yes | yes | Packets leaving the repacketizer |
| `npkts_resizer_discard` | integer | yes | yes | Packets the repacketizer dropped |
| `npkts_discard` | integer | yes | yes | Packets dropped |
| `total_duration` | decimal string | yes | yes | Summed session duration in seconds |
| `ncmds_rcvd` | integer | yes | yes | Control commands received |
| `ncmds_rcvd_ndups` | integer | yes | yes | Commands that were cookie retransmissions |
| `ncmds_succd` | integer | yes | yes | Commands that succeeded |
| `ncmds_errs` | integer | yes | yes | Commands that failed |
| `ncmds_repld` | integer | yes | yes | Replies sent |
| `rtpa_nsent` | integer | yes | yes | RTP analyzer: packets sent |
| `rtpa_nrcvd` | integer | yes | yes | RTP analyzer: packets received |
| `rtpa_ndups` | integer | yes | yes | RTP analyzer: duplicates seen |
| `rtpa_perrs` | integer | yes | yes | RTP analyzer: parse errors |
| `rtpa_nlost` | integer | **no** | yes | RTP analyzer: packets lost |

Twenty-seven on 2.1.1, twenty-eight on 3.2.0. **`rtpa_nlost` is the difference**,
and it is the one an operator asking "is the relay losing my audio" wants. On
2.1.1 it is a per-session counter only, reachable through `Q`.

`total_duration` arrives as `90.010078` — a decimal STRING, not an integer.
Every other name above is an unadorned integer. A decoder that assumed one type
for the whole namespace would get this one wrong.

### The free-text form (`I`)

`I` returns five lines of prose:

```
sessions created: 1
active sessions: 0
active streams: 2
packets received: 9000
packets transmitted: 9000
```

`Ib` returns the same five lines. These are a HUMAN rendering of counters that
`G` also answers, except `active sessions` and `active streams`, which have no
`G` name at all: `G active_sessions` returns `E68` on both versions. So `I` is
not redundant, and a reader who needs the live session count has only this
form.

`I`'s first word is `sessions`, which begins with the stop-play command letter.
That is why the control decoder refuses a reply on content as well as on
direction — see [`docs/internals/relay-control-decoding.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/relay-control-decoding.md).

## rtpproxy: the per-session counters (`Q`)

`Q <call-id> <from-tag> [<to-tag>]` returns five positional fields:

```
Q 1-91@172.28.0.21 91SIPpTag091;1 1SIPpTag018;1
60 3381 3381 6762 0
```

The positions were undocumented here and are now answered from the relay's own
format strings, which both builds carry verbatim:

```
%d %lu %lu %lu %lu
ttl=%d npkts_ina=%lu npkts_ino=%lu nrelayed=%lu ndropped=%lu
```

So the five are, in order: **`ttl`, `npkts_ina`, `npkts_ino`, `nrelayed`,
`ndropped`**. The named rendering is not a reading of the source — it is a
second format string in the same binary, and `Qv` prints it:

```
Qv 1-91@172.28.0.21 91SIPpTag091;1 1SIPpTag018;1
ttl=60 npkts_ina=3954 npkts_ino=3954 nrelayed=7908 ndropped=0
```

The arithmetic corroborates the labels independently: `nrelayed` is exactly
`npkts_ina + npkts_ino` in both samples. **ST3's open question is answered, and
these fields are in scope.**

`Q` also accepts an explicit counter list, returned in the order asked:

```
Q <call-id> <from-tag> <to-tag> ttl ndropped   ->  60 0
Q <call-id> <from-tag> <to-tag> rtpa_nlost     ->  0
```

The per-session counter names are `ttl`, `npkts_ina`, `npkts_ino`, `nrelayed`,
`ndropped` and `rtpa_nlost`. `rtpa_nlost` is reachable here on 2.1.1 even
though `G` refuses it, which is how a relay that cannot report loss globally
still reports it per call.

### The tag a capture sees is not the tag the relay holds

`Q` with the tags as they appear on the wire fails:

```
Q 1-91@172.28.0.21 91SIPpTag091 1SIPpTag018
E50
```

and the relay's own log says why: `query request failed: session
1-91@172.28.0.21, tags 91SIPpTag091/1SIPpTag018 not found`. OpenSIPS appends a
`;1` viabranch suffix, and the session is keyed on the suffixed form. Anything
correlating a captured dialog to an rtpproxy session must account for it, and
must not conclude from `E50` that the relay is not holding the call.

**rtpengine does not do this.** Its per-call reply keys tags as they appear in
the SIP message, unsuffixed. The two relays differ here, and a correlation rule
written against one silently fails against the other.

### The refusal codes are distinct, and they mean different things

| Code | Seen on | Means |
|---|---|---|
| `E68` | `G <unknown>` | No such global statistic in this build |
| `E62` | `Q … <unknown>` | No such per-session counter |
| `E50` | `Q <call-id> <tags>` | No session with that call-id and those tags |
| `E19` | `Qz …` | Unknown command modifier |
| `E1` | `Q` with nine arguments | Too many arguments |

A caller must not collapse these. "The relay does not know that name" and "the
relay is not holding that call" are different answers to an operator, and only
the second is about their call.

## rtpengine: the global statistics (`statistics`)

One ng command returns a nested dictionary. On 12.5.1.31-1, against a relay
with one interface and two control peers, it carries **250 leaf values** under
seven sections. The total is deployment-specific: two of the seven are lists
whose length follows the configuration, so a fixed expected count is not a
property of the version.

| Section | Shape | What it holds |
|---|---|---|
| `currentstatistics` | flat dict, 16 keys | Instantaneous rates and session counts |
| `totalstatistics` | flat dict, 24 keys | Cumulative counters since start |
| `interfaces` | **list** of dicts, 46 leaves for one interface | Per-interface ports, byte and packet totals, and a nested `voip_metrics` |
| `mos` | flat dict, 5 keys | Aggregate MOS |
| `voip_metrics` | flat dict, 30 keys | Aggregate jitter, loss and round trip |
| `transcoders` | **list**, empty on a relay that transcoded nothing | Per-codec-pair transcoding counts |
| `controlstatistics` | dict of 26 keys, one of them a **list** of `proxies` | 25 `total…count` totals, plus one entry per control peer with that peer's own counts and durations |

Three of the seven are lists — `interfaces`, `transcoders`, and `proxies`
inside `controlstatistics` — and `proxies` has one entry per control peer,
which includes whoever is asking. A flattening that assumed a tree of scalars
would lose the interface a figure belongs to, and would report sipnab's own
queries as somebody else's traffic. `transcoders` came back as an empty LIST,
not an absent key and not an empty dict, so a reader that tests for a mapping
finds the wrong shape on any relay that has transcoded nothing.

### Numbers arrive as two different bencode types

```
"relayedpackets":      9000          integer
"relayedbytes":        1548000       integer
"uptime":              "134"         STRING that looks like an integer
"jitter_average":      "0.000000"    string
"used_pct":            "7.84"        string
"avgcallduration":     "0.000000"    string
```

`uptime` is the trap: a whole number, delivered as a string, beside dozens of
whole numbers delivered as integers. Any decoder that switches on the bencode
type to decide how to render a value will render this one differently from its
neighbors for no reason a reader can see.

**The rule that follows: return the relay's own names and the relay's own
values, and let the caller ask for the one it wants.** Do not normalize a type
per key, because the key set is version-specific and the type is not stated
anywhere the relay publishes.

### The sections that count sessions disagree, legitimately

On a run that had relayed 9000 packets:

```
currentstatistics/sessionstotal    1
totalstatistics/managedsessions    0
totalstatistics/relayedpackets     9000
```

`managedsessions` counts sessions that have COMPLETED. A session still up is in
`currentstatistics` and not yet in `totalstatistics`. Adding the two, or reading
either as "calls this relay has handled", produces a number that is wrong in a
way nothing in the reply signals.

## rtpengine: the per-call view (`query`)

`query` with a `call-id` returned 144 leaf values for a two-tag, one-media
call. The shape is
`tags -> medias[] -> streams[]`, with `ingress SSRCs[]` and `egress SSRCs[]`
under each stream, plus a `totals` block split by `RTP` and `RTCP`.

Per stream it reports `stats` (in) and `stats_out` (out), each with `packets`,
`bytes` and `errors`; the local address and port it allocated; the endpoint it
latched and the endpoint the SDP advertised, separately. Per SSRC it reports
`packets`, `bytes`, `last RTP seq` and `last RTP timestamp`.

Several keys contain **spaces**: `last kernel packet`, `last user packet`,
`advertised endpoint`, `ingress SSRCs`, `last RTP seq`. A flattened dotted name
built from these is ambiguous unless the separator cannot occur in a key, which
a dot can and a space does.

## What this settles, and what it does not

Settled:

- ST3's open question. The five `Q` fields are named, corroborated twice, and
  in scope.
- The vocabulary is the relay's, per version, asked at runtime. No frozen
  schema.
- Refusals are distinct and must stay distinct.
- Tag correlation differs between the two relays.

Not settled here, and belonging to ST-S1:

- Which of these are safe to aggregate with sipnab's own measurements, and
  which are not. `rtpa_nlost` and a loss figure sipnab computed from sequence
  gaps are both "loss" and are not the same number.
- How a missing value is rendered so it never reads as a zero one.

## A gap this inventory exposes

The harness runs rtpproxy 2.1.1 while the version this project has been
reasoning about is 3.2.0. They differ by a counter — `rtpa_nlost` — that an
operator specifically wants. A test written against the harness alone would
never exercise the version-difference path, which is the path most likely to
break in the field. Either the harness gains a 3.2.0 build, or the tests drive
the decoder against recorded replies from both. Recorded here so the choice is
made deliberately rather than by whoever writes the first test.
