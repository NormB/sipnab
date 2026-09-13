# What the documentation and the site must teach (ST-S5)

**Norm, 2026-09-12:** "the documentation and web site must be improved to
highlight these capabilities and show the operator how to use them. the
cookbook and examples must be improved specifically."

This gates ST-D1 (the cookbook) and ST-D2 (the site). It assumes the vocabulary
in [`relay-statistics-vocabulary.md`](relay-statistics-vocabulary.md), the
surface contract in [`relay-statistics-surfaces.md`](relay-statistics-surfaces.md),
and the inventories in [`relay-statistics-inventory.md`](relay-statistics-inventory.md).

## The one thing the docs must not let an operator believe

A relay statistic is a claim from a box, not a measurement sipnab made. The
single failure this documentation exists to prevent is an operator reading
`npkts_relayed: 9000` and concluding sipnab saw 9000 packets. It did not; the
relay said so. Every recipe that shows a relay number shows, in the same
breath, which of the three tiers it belongs to and what that means for trust.

This is the tier rule from ST-S1, written for an operator rather than as a type
name. The docs never use the words `relay_reported` / `sipnab_measured` /
`endpoint_reported` as their primary teaching; they say "the relay's own count",
"what sipnab saw on the wire", "what the far end claims", and attach the wire
name once so a reader can match it to the JSON.

## Per capability, the docs answer three questions

For each of the five capabilities in the surface contract, the documentation
states, in this order:

1. **The question an operator actually has.** Not "how to call `relay_stats`"
   but "is the relay dropping my packets". The task, in the operator's words,
   is the heading.
2. **The command or click that answers it, on the surface the reader is on.**
   The cookbook leads with the CLI; each recipe links the REST, MCP and TUI
   spellings rather than repeating them, because the surface contract already
   holds those four in sync and a fourfold copy drifts.
3. **What the answer does NOT tell them.** The caveat is not a footnote. It is
   the half that keeps the number honest: the counter resets on restart and
   rtpproxy will not say so; the per-call tags are the relay's, not the wire's;
   a figure absent from the reply was not asked for, and a zero means the relay
   counted zero.

## The cookbook (ST-D1): the recipes that must exist

The cookbook is [`docs/examples.md`](https://github.com/NormB/sipnab/blob/main/docs/examples.md), published at `/docs/cookbook/`. It is
already task-first — "What do you want to do?" maps a question to a numbered
recipe — and the new recipes join that table. At minimum, one per question an
operator brings to a relay:

| The operator's question | What the recipe shows | The caveat it must carry |
|---|---|---|
| Is this relay dropping packets? | The relay's own drop and relay counters, asked live | A reset relay reads as a quiet one; show `uptime` beside them where the relay has it, and say rtpproxy has none |
| Is it holding sessions nobody released? | Active-session and created/destroyed counts | "Active" is this instant; a session torn down a second ago is already gone from it |
| Does the relay's view of THIS call match mine? | The compare capability (C4), both figures side by side | The two count different sockets over different windows; a difference is not automatically a fault, and three ordinary causes are named |
| Is what the relay reports about loss the same thing my capture measured? | The relay's loss counter beside sipnab's sequence-gap loss | **The recipe most likely to be got wrong without the tier rule.** They are both "loss" and are not the same number; neither is authoritative over the other |

That last recipe is the tier rule in practice, and the spec names it as the one
that fails hardest when an author forgets it. It is written even if it is the
only statistics recipe that ships.

## The site (ST-D2): surfacing the capability, not burying it in a flag table

**A capability an operator cannot find does not exist for them.** Today relay
statistics would be discoverable only by reading a flag reference top to bottom.
ST-D2 requires:

- The homepage capability table names relay statistics as a row of its own,
  with the tier caveat in one clause, not folded into the existing "REST API"
  or "MCP server" rows. It links the cookbook recipe, not the flag.
- The docs navigation carries the statistics page where an operator looking for
  it would look — beside the relay pages (`rtpengine.md`), not only under a CLI
  reference.
- Runnable examples on the relevant pages, held by the two gates that already
  hold every other example: `doc_example_coverage_test` (two examples per flag)
  and `doc_commands_run_test` (every documented command runs, or is a named
  exception). A statistics flag added with no example fails the first; an
  example that sipnab refuses fails the second.

## Every example runs before it ships

**The release-verification lesson applies to documentation too: an example
nobody executed is a claim, and a copied command that fails is worse than no
example because the reader blames themselves.**

This is no longer aspirational. `doc_commands_run_test` runs every `sipnab`
command in `docs/` against a capture that ships with the repository, or places
it in a named never-run bucket. A statistics recipe that transmits to a relay
falls in the `Bounded` bucket if it binds or the `ReadsFakeDevice` bucket if it
names a device; one that only reads a capture runs outright. The spec's
requirement is therefore concrete: a recipe whose command cannot be made to run
or to fall in a named bucket is not finished.

The relay examples have a second home: the harness. `ST-D2` says every site
example must run against the harness before it ships, and the harness now runs
both relays side by side (see the anchor tests), so a `query_relay` example can
be exercised against rtpengine and an `I`/`G` example against rtpproxy on one
stack.

## What this spec does not decide

- The exact recipe numbers and their order in the cookbook. ST-D1 places them;
  this says which questions they must answer.
- The wording of the homepage row. ST-D2 writes it; this says it must be its
  own row, must carry the tier caveat, and must link a recipe.
- Anything about statistics sipnab has not yet implemented. ST1–ST9 build the
  capability; this builds the path an operator takes to find it, and neither
  ships before the other — a documented capability that does not exist is the
  same lie as an undocumented one, in the other direction.
