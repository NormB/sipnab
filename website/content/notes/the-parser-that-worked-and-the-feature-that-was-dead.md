+++
title = "The parser worked, its tests passed, and the feature was dead"
date = 2026-09-05
description = "SIPREC metadata had a parser, unit tests and a field on the dialog. It was never filled on a live capture, because the fault sat between the parser and the store where no unit test could see it."

[extra]
kind = "postmortem"
+++

sipnab has parsed SIPREC recording metadata (RFC 7866) for a long time. There
is a parser, `src/sip/siprec.rs`. It has unit tests, and they pass. A
field on the dialog, `siprec_metadata`, holds the result, and code fills it.

On a live capture that field was never filled. Not sometimes. Never.

## Three defects, each one layer further in

The first two were in the parser, and both came from the same cause: the tests
used a fixture somebody composed by hand rather than one taken from something
that sends SIPREC. It nested `<participant>` and `<stream>` inside `<session>`
and put the address-of-record in an `<aor>` child element. A real session
recording client emits them as siblings of `<session>`, with `aor` an attribute
of `<nameID>`.

So the tests asserted the shape their author imagined, and they passed. Against what
OpenSIPS's `siprec` module actually writes — read out of
`modules/siprec/siprec_body.c`, not out of the RFC — two fields were dead. The
recording mode is `<datamode>`. sipnab looked for `<mode>` and found nothing.
And stream ownership is not in the stream element at all: it lives in
`<participantstreamassoc>`, whose `<send>` children name what a participant
originates and whose `<recv>` children name what it merely hears. sipnab looked
inside `<stream>`, where no SRC puts it, so every stream came back unowned.

That second one mattered most, because it is the whole reason to carry this
metadata. The only route from a recorded stream back to a person runs through
that association.

## The third one was not in the parser

`DialogStore::process_message` has three arms that apply the state a message
contributes to its dialog: one for a dialog that already exists, one that
creates a dialog, and a replay that runs after a merge. Two of them parsed
SIPREC. The creating arm did not.

An SRC puts its metadata on the INVITE that opens the recording dialog. That
INVITE is, by definition, the message that creates the dialog. So the one arm
that skipped the parse was the only arm that would ever have seen the metadata.

Nothing about this is visible from inside the parser. Its tests hand it bytes
and check what comes back, and it was right about those bytes the whole time.
The defect was in the wiring between a component and its caller, and the only
thing that shows that is a capture read end to end through the real binary.

## What we changed, beyond the bug

The rule is one function now, called from all three arms. Three copies existed and one
of them was wrong, which is the ordinary outcome. Write a rule three times and
somebody eventually writes it twice.

The fixtures come from the generator. Where a peer produces the bytes we parse,
the tests take their material from that peer's source rather than from a
reading of the specification. The specification says what a sender may send.
The peer says what it does send.

And the parser now has a reader. The metadata reaches MCP, REST, the CLI report
and the call-flow ladder. That is not a separate improvement — it is the same
lesson. Nobody can observe a parser with no reader failing, and this one failed for
exactly as long as it had none.
