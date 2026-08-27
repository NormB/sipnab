+++
title = "What 0.5.128 added to the vCon exporter"
date = 2026-08-27
description = "Seven fields the format defines and sipnab was not emitting, transfer objects for observed REFERs, a configurable media ceiling, tombstones for withheld dialogs, and RFC 9457 errors. What each one is for."

[extra]
kind = "feature"
+++

0.5.128 closed every open item on the vCon backlog. Most of them add something
a consumer can read. Two change what an existing field means. Here is what each
one does and why you might care.

## Fields the format defines that sipnab was not sending

**`subject`** now names the dialog: `SIP call <call-id>`. A store whose search
matches subject or UUID substring could previously find a sipnab container only
by a UUIDv8 nobody has memorized. It stays purely descriptive — an observer is
in no position to say what a conversation was *about*, and a subject that tried
would be the one field in the container asserting something nothing measured.

**`party.name`** carries the display name from the `From`/`To` header under the
key consumers actually read. It travels beside `validation: "none"`, and that
pairing is what keeps it honest. One of our own test captures makes the point
better than any argument: SIPp puts the codec in the display name, so the
caller's `name` reads `PCMU/8000`. sipnab reports it faithfully because that is
what the wire said, and the `validation` field beside it is the signal against
reading it as an identity.

**`party.stir`** carries an observed RFC 8224 PASSporT — the JWS alone, without
the `info`, `alg` and `ppt` parameters, because a consumer handed the whole
header value cannot parse it as a token. It rides on the caller, since that is
who the `Identity` header authenticates. sipnab fetches no certificate and
checks no signature, so it is evidence a consumer may verify, never a verdict.

**`session_id`** carries the RFC 7989 pair. This is the identifier that
survives a B2BUA where `Call-ID` does not, and it is the draft's own
leg-correlation mechanism. sipnab drops a `nil` or malformed half rather than
transcribing it: a correlation key that matches nothing is worse than an absent
field, because absence is readable and a dead key is not.

## Transfers

An observed REFER now produces a `transfer` Dialog Object naming the
transferor, the transferee and the target, all as party indices — so the
`Refer-To` party joins the array to have an index to point at.

An *attended* transfer, which a `Replaces` parameter in the `Refer-To` URI
identifies, points its `consultation` at an empty Dialog Object. That is not an
invention: issue #9 on the draft asks what to do for a transfer whose
consultative call was never captured, and issue #20 answers it with `{}` after
discussion at IETF 124. A blind transfer names no `consultation` at all, and
the presence of the member is what tells the two apart.

## Two changes to existing behavior

**A Dialog Object carrying nothing now names no `type`.** It used to say
`incomplete`, a value the draft reserves for a call that never began — so
every signaling-only container for a call that answered reported a failure that
never happened. [The full story is its own
note](@/notes/the-container-that-said-every-call-failed.md).

**REST errors carry RFC 9457 `application/problem+json`.** They used to be a
bare status code with no body, so a client got a number and had to guess which
of a handler's several 400s it had hit. The `type` URI is the member to branch
on, and its slug derives from the status rather than from free text at each
call site, so one kind of failure has one identity across every endpoint.

## Three new flags

`--vcon-max-inline-media MIB` raises or lowers the inline audio ceiling.
[A how-to covers it](@/notes/keep-the-audio-your-store-will-not-take.md).

`--content-deny-tombstone` writes an identity-only container for a dialog your
deny header suppressed, declaring `redacted` with `type` alone. It is off by
default, and deliberately: a tombstone reveals that the call *existed*. If your
header means "this call must leave no trace", leave it off.

`--vcon-digest` prints `<sha256>  <filename>` per container in `sha256sum`
format, on stdout while progress stays on stderr — so `--vcon-digest >
SHA256SUMS` produces a file `sha256sum -c` reads. It is a digest and not a
signature, because a signature over sipnab's bytes could never verify against
the object a store holds after a conserver adds fields on ingest.

## And one thing that was quietly broken

`--export-vcon-dir` is a queue an external bridge polls, and it wrote with
`std::fs::write` — which truncates the destination and then fills it. Every
byte of the write was a window in which the file existed and was invalid, and a
failure inside that window destroyed the previous container too. Both write
paths now stage under a dot-prefixed sibling, flush, rename, and sync the
directory so the rename itself survives a crash.

If you consume that spool, the contract is now written down under [The spool
contract](@/docs/vcon.md).
