+++
title = "One call, two nodes, and neither saw the whole thing"
date = 2026-09-01
description = "The SBC says it sent the call, the PBX says it never arrived, and a B2BUA changed the Call-ID in between. How to join the two legs, and how to tell an identifier match from a guess that scored well."

[extra]
kind = "howto"
+++

The SBC log says it forwarded the call. The PBX log has no such call. Both are
right, because a back-to-back user agent gave the outbound leg a new Call-ID
and neither box ever held both identifiers at once.

You hold two captures. The work is joining them, and the trap is that the
joining tool answers with a number that looks the same whether it matched an
identifier or guessed from a clock.

## Ask the box that saw both sides first

Whichever node re-originated the call is the only one that held both legs, so
its answer names the Call-ID to carry inward. Ask it, then follow the pointer:

```bash
sipnab --mcp -N --quiet --node-name sbc-edge-1 -I sbc.pcap
```

Then call `find_correlated` with the leg you already know. On a capture holding
a B2BUA, the answer looks like this:

```jsonc
// find_correlated { "call_id": "b2bua-caller-synth@203.0.113.1" }
{
  "source_call_id": "b2bua-caller-synth@203.0.113.1",
  "legs": [
    { "call_id": "b2bua-leg-synth@203.0.113.101:5060", "score": 50,
      "strategy": "timing_heuristic", "identifier_match": false,
      "observed_gap_ms": 3 }
  ],
  "total_matched": 1,
  "heuristic_only": true,
  "capture_identity": { "node": "sbc-edge-1" }
}
```

Ask the PBXes first instead and you are guessing which one took the call, which
usually means asking all of them. Server-side query time runs under a
millisecond while an agent round trip costs seconds, so following one pointer
beats fanning out by a wide margin.

Ask the re-originating box even when you expect it to stay a proxy on this
call. If it did, `find_correlated` returns nothing and you carry the same
Call-ID inward for the price of one query. If it did not, you now hold the
identifier the next hop knows the call by.

## Read the strategy, not the score

Here is the same tool on a different capture:

```jsonc
{ "score": 90, "strategy": "sdp_origin",
  "identifier_match": true, "observed_gap_ms": null }
```

Score 90 against score 50, and the gap between them is much wider than 40
points. The first answer matched an [RFC 8866](https://www.rfc-editor.org/rfc/rfc8866)
SDP origin tuple, which two legs share only when something forwarded the SDP
untouched. The second matched nothing at all — it found a dialog on the same
endpoint three milliseconds later and said so.

`identifier_match` carries that difference as a boolean, so a client can filter
on it without learning which strategy names mean what. `heuristic_only` says
whether EVERY returned leg came from a guess, which is the flag an agent needs
before it writes a conclusion — a call tree built only from timing is a
hypothesis, and one presented as a finding is worse than no answer.

`observed_gap_ms` appears only for `timing_heuristic`, and there it IS the
evidence. A 15 ms gap on a quiet box and a 1,900 ms gap on a busy SBC score
identically and mean completely different things.

The strategies that survive a B2BUA by design are few. `session_id` matches an
[RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) `Session-ID`, which exists
for exactly this. `charging_vector_related_icid` matches when one leg's
[RFC 7315 §4.6.4.1](https://www.rfc-editor.org/rfc/rfc7315#section-4.6.4.1)
`related-icid` names the other's `icid-value`, and a B2BUA emits that only when
it chose to. Everything else survives a proxy and not a re-origination.

Most deployments emit no correlation header at all. Where none appears, the
timing guess is the only strategy left, and on a busy SBC unrelated calls
routinely share an endpoint inside its window. The full strategy table, with
which of them survives a B2BUA and why, is on the
[MCP tools page](@/docs/mcp-tools.md).

## The clock is part of the evidence

When the strategy is timing, the answer carries what sipnab knows about the
clock underneath it:

```jsonc
"timing_clock": { "available": true, "synchronized": true,
                  "est_error_us": 0, "max_error_us": 349000 }
```

Read `max_error_us` against `observed_gap_ms` before believing a timing match.
A 3 ms observed gap sitting under a 349 ms error bound is not a measurement of
3 ms — it is a measurement somewhere inside a window two orders of magnitude
wider. That does not make the match wrong. It makes the gap useless as a
discriminator between this leg and any other leg on the same endpoint inside
that window.

`--leg-correlation-window` is the only knob the timing heuristic has, and the
shipped two seconds describes a PBX that places the outbound leg immediately.
A PBX doing a number-portability lookup, an ENUM dip, or walking a
least-cost-routing cascade before it dials takes longer than that, and no
setting of anything else reaches a leg paced wider than this window.

Between two captures on two machines the same caution applies twice over. A few
hundred milliseconds of skew makes an ordinary exchange look like a
retransmission, so check NTP on both hosts before reading a timing difference
as evidence about the call.

## Name your nodes before you need to

Every MCP and REST answer carries `capture_identity.node`, and that string is
the only thing attributing a fact to a box. "Answered with 407" is an
incomplete finding until you know which machine said it.

```ini
ExecStart=/usr/local/bin/sipnab --mcp -N --mcp-transport http \
    --mcp-bind 127.0.0.1:8731 --node-name sbc-edge-1 -d eth0
```

`--node-name` defaults to the system hostname, which is usually what you want
and occasionally not — the default puts your hostname on the wire. Set it to
something you recognize in a transcript six weeks later. It stays put across a
capture restart, while `capture_identity.instance` rotates whenever a different
capture loads, so the pair tells a topology change apart from a reload.

## What the join cannot prove

Two legs correlated across two captures still leave one thing unestablished:
that the messages you are comparing are the same messages. Both captures may
hold a leg, agree on timing, and differ in a header that a middlebox rewrote.
`compare_dialogs` is what surfaces that, and it is worth running even when the
correlation looks certain.

An SBC that changes SDP addresses is doing its job. One that drops a header is
not. That distinction is the reason to compare rather than to stop at a
matching Call-ID.

## The order

1. Query the box that re-originated, not the ones downstream.
2. Read `strategy` and `identifier_match` before `score`.
3. If `heuristic_only` is true, say so in whatever you write next.
4. Check `max_error_us` against `observed_gap_ms` before trusting a timing
   match, and check NTP before trusting a cross-capture one.
5. Compare the dialogs, because a correlated leg is not necessarily an
   unmodified one.
