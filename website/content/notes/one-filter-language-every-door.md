+++
title = "One filter language, every door"
date = 2026-09-01
description = "The same expression narrows --filter, decides which calls export as vCons, scopes a CI expectation and pages an MCP tool. Why reusing one language beats growing a flag per policy, and what an unmeasured value matches."

[extra]
kind = "feature"
+++

sipnab has one declarative, non-Turing-complete language for selecting dialogs,
and it turns up wherever a surface needs to say *which calls*. Learning it once
buys every door.

```bash
sipnab -N -I capture.pcap --filter "response_code == 503 AND dst.ip == '198.51.100.7'"
```

That same string is what you put in the `[filter] expression` config key, what
`--export-vcon-when` takes to decide which dialogs become containers, what an
expectation rule's `scope = "filter:..."` narrows a CI gate with, and what the
`filter` parameter on the MCP query tools accepts. `validate_filter` compiles
one and tells you what it selects without spending a page of rows on the
answer.

## Why reuse beats a flag per policy

The alternative was visible when conditional vCon export landed. It could have
grown one export flag for failed calls, another for calls over thirty seconds,
another per carrier. Each of those enumerates a case somebody thought of, and
the case nobody thought of is the one an operator needs at three in the
morning. Reusing the language sipnab already speaks covers all of them and adds
no vocabulary to learn.

The same argument holds in the other direction for the diagnostic aliases. Ten
of them name preset expressions — `problems`, `slow-setup`, `short-calls`,
`one-way`, `nat-issues`, `codec-asym`, `ptime-asym`, `payload-asym`,
`duration-asym`, `late-media` — and each one has up to three spellings: a
dedicated CLI flag where one exists, `--filter <alias>`, and a `kinds` entry on
the MCP `find_problems` tool. All three expand to one expression, so
`sipnab --short-calls`, `sipnab --filter short-calls` and
`sipnab --filter "duration < 3.0 AND state == 'Completed'"` select the same
dialogs. `--filter` resolves its argument as an alias first and parses it as an
expression only when no alias matches, which is what makes the two spellings
interchangeable rather than merely similar.

## What an unmeasured value matches

Nothing. This is the rule most worth knowing before you write a saved filter.

`pdd`, `setup_time`, `rtp.mos`, `rtp.jitter` and `rtp.loss` are **unknown**
when the capture holds nothing to measure them from — no RTP for the media
fields, no captured INVITE or 200 OK for the timing ones. An unknown matches no
numeric operator, `!=` included: it is not "different from 3.0", it is unknown.
That is the rule SQL uses for `NULL`, for the same reason.

Reading them as `0` instead would put every unmeasured call below every
threshold anyone would type, so `rtp.mos < 3.0` would select every call
carrying no media at all — 2292 of 2311 dialogs on one real trunk capture,
rather than the 2 genuine ones. To ask about calls that carry no media, ask for
that directly: `rtp.packets == 0` is a real count of zero, and `no_media` is the
diagnosis itself. Pairing an `rtp.*` threshold with `rtp.packets > 0` is
redundant rather than wrong, and it reads clearly.

`response_code` follows the same discipline. A call still in progress has no
final response, so it matches nothing — not `< 400`, not `>= 400`, not `== 0`,
because a zero default would sweep every ringing call into the success bucket.

One field name the parser refuses outright is `rtp.orphaned`. It would ask
whether a stream *belonging to this dialog* belongs to no dialog, and a stream
is an orphan exactly when no dialog claims it, so the two halves exclude each
other: the field would match nothing on any capture while `NOT rtp.orphaned`
matched everything. Rejecting it at the parser beats a silent falsehood.
Orphaned media stays reachable through surfaces that model streams rather than
dialogs — the "Orphaned Streams" section of `--report`, and
`/v1/streams?orphaned=true`.

## What it narrows, and what it does not

A filter selects **dialogs**, and every listing output honors that. The
per-message stream emits only messages belonging to matching dialogs,
`--json-dialogs` emits one line per matching dialog, and `--report` prints only
matching dialogs with the RTP tables beneath holding only their streams.

`--call-report <CALL-ID>` is deliberately not narrowed: it names one call, and
a lookup by name is not a listing.

The per-message match is a different tool. `-e`/`--match` is the
sngrep-style match expression — it selects matching messages and then follows
the dialog, emitting everything after the first match. The `payload` DSL field
is the per-dialog version, true when any message in the dialog matches, and it
composes inside a larger expression the way a flag cannot.

The language has no comment syntax, so a `#` line handed to `--filter` is a
parse error rather than a note. String comparisons are case-sensitive, and
`=~` takes a Rust regex compiled once and reused across the capture.

## Telling it works

`validate_filter` exists because trying an expression used to cost a page of
rows. It compiles the expression, counts what it selects, and returns no rows
at all — and a **parse failure is a successful call**, answering `valid: false`
with the parser's own text, position and caret included. Every other tool
rejects a bad filter as an error object, which is right there and wrong here:
learning what is wrong with an expression is this tool's entire job, and an
error channel is where a model acts on a message least.

`total_matched` stays `null` on a parse failure rather than dropping to `0`,
because a zero there reads as "parsed, matched nothing" — the opposite of what
happened.

[The filter DSL reference](@/docs/filter-dsl.md) has every field, operator and
alias, with the expansion each alias resolves to.
