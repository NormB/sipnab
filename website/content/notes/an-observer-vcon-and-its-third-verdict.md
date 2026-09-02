+++
title = "An observer's vCon, and its third verdict"
date = 2026-09-01
description = "sipnab writes a conversation container from a tap: nothing signed, no vouched-for name, audio inline only when the run kept it, and a block stating what the capture missed. Plus why the container validator has three verdicts rather than two."

[extra]
kind = "feature"
+++

Something downstream wants the call rather than the packets. A conversation
archive, a compliance store, an agent reasoning over calls: hand any of them a
pcap and the decoding becomes their problem. vCon is the interchange container
those systems already read, and sipnab writes one per observed dialog.

The export sits behind the non-default `vcon` Cargo feature, which `full`
carries. A build without it refuses the flag by name rather than exporting
nothing.

## What kind of container this is

The ecosystem around the format assumes a **recorder** — something inside the
conversation, which took the media from a party and can say what that party
agreed to. A recorder can write *"I received this audio from the caller."*

sipnab reads a mirror port. The strongest sentence it can honestly write is *"I
saw packets claiming to be this call go past this tap."* Those two sentences
look alike in JSON and mean entirely different things, so sipnab emits
**observer** vCons: the container names sipnab as a passive party contributing
to a record somebody else owns, a role the format itself defines, and stops
there.

Four consequences follow, and each one is a refusal rather than a gap.

**Nothing carries a signature.** No JWS, no JWE. A signature over an
observation verifies as a signature over a recording, and encryption asserts a
custody relationship sipnab does not have. Trust a sipnab container exactly as
much as you trust whoever handed it to you.

**No party carries an established name.** `party.name` exists and carries the
display name from `From` or `To`, so a generic reader shows a named party
rather than an anonymous one. What sipnab refuses is not the field but the
*claim*: `validation` reads `"none"` unconditionally, which says a header
asserted this name and nobody checked it. One of our own test captures makes
the point better than an argument — SIPp puts the codec in the display name, so
a caller's `name` reads `PCMU/8000`. Treat the field as personal data, and key
any redaction step on `name` **and** `sip_display_name`.

The one identifier sipnab does supply is `tel`, and only when the SIP user part
is unambiguously a telephone number: `+` followed by digits, an RFC 3966 global
number. A bare `1001` is an extension, and indexing it as a telephone number
would put a wrong answer in a search index rather than no answer.

**Audio rides inline, or not at all.** When the run retained the RTP payload
the container carries the audio as a `recording` Dialog Object with a `sha512-`
content hash. When it did not, the container says so in words and carries none.
There is never a `url`, because sipnab hosts nothing and cannot promise where a
file lives tomorrow. Audio over the inline ceiling
(`--vcon-max-inline-media`, 5 MiB by default) draws an out-loud refusal naming
the size and the budget, rather than a silent truncation —
[a how-to covers that ceiling](@/notes/keep-the-audio-your-store-will-not-take.md).

**Every absence describes the capture, never the conversation.** A `dialog[]`
object with no media fields says this export carries no media. It does not say
the call had none.

## The block that states what the capture missed

vCon has no field for incompleteness. Not a weak one — none. The `type` enum
admits five values, four of which promise content the object holds and the
fifth of which names a call that failed to set up. So sipnab types a Dialog
Object by **what it carries**, never by what the call did, and duplicates the
caveat into two surfaces a consumer walks past: `capture_completeness` inside
`analysis[0].body`, and a `sipnab-capture-completeness` attachment attributed
to the observer. Both hold the same value byte for byte, and a test fails if
they diverge.

Every clause in it measures the run. `undecodable_frames`,
`messages_evicted`, `sip_discarded_by_port_gate`, `frames_read` — and the prose
sentence beside each number moves with it, so a consumer reading fields reaches
the same verdict as one reading words. Two fields in the block report a
**decision** rather than a fault, and the note says so: `gate_closed_during_run`
and `dialogs_suppressed_by_deny`. Both are always present, including as `false`
and `0`, because a reader who cannot tell a chosen absence from a missed one
goes looking for a fault that does not exist.

## Three verdicts, and why the middle one exists

Run the containers past `validate_vcon` before handing them to a conserver. A
store that refuses one reports the refusal to whoever POSTed it, never to
whoever built it — and a validation pass over 4,216 real containers found 2 the
schema rejects, with nothing on any surface saying so.

| `verdict` | What it means |
|---|---|
| `valid` | Nothing disagrees with the schema |
| `valid-except-documented-deviation` | Every finding is a shape sipnab emits on purpose that the schema rejects |
| `invalid` | At least one finding is an ordinary defect |

The middle verdict carries the whole point. Section 4.3 of the draft says it is
possible to have a Dialog Object with no parameters in it, the working group
agreed that shape in issue #20 after IETF 124, and the draft's own Appendix B
schema forbids it, because every Dialog Object requires a `start`. sipnab emits
one: the consultative call of an attended transfer, which the observed leg
never saw.

Folding that into a clean pass would teach a producer that a missing `start` is
fine — and a missing `start` on a `transfer` object is exactly the defect the
corpus pass found. So the exemption is narrow. ONLY a Dialog Object with no
members at all counts as the documented deviation. A typed object missing
`start` is an error, and the two never merge.

A container that disagrees with the schema is an ANSWER rather than a tool
error. The call fails only when the request itself is wrong: neither argument,
both, an unknown `call_id`, or a `container` that is not a JSON object.

## Telling it works

Every door builds the same bytes — `--export-vcon` with `--vcon-out`,
`--export-vcon-when` into `--export-vcon-dir`, the `export_vcon` MCP tool, and
`GET /v1/dialogs/{call_id}/vcon`. Take one container and check it:

```bash
sipnab -N -I capture.pcap --export-vcon 'CALL-ID' --vcon-out out.json
```

Then ask `validate_vcon` for a verdict, and read the completeness block before
you read the counts. [The vCon page](@/docs/vcon.md) has the full contract,
including the spool guarantees a bridge draining `--export-vcon-dir` may rely
on, and [a companion note](@/notes/what-0-5-128-added-to-the-vcon-exporter.md)
covers what 0.5.128 added to the exporter.
