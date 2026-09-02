+++
title = "Hand over evidence somebody else can check"
date = 2026-09-01
description = "You found the answer. Now a carrier that does not trust you has to confirm it. Four artifacts, each answering a different doubt, and the one thing sipnab deliberately refuses to claim."

[extra]
kind = "howto"
+++

The investigation is the easy half. The hard half starts when the answer has to
survive contact with a reader whose interest runs the other way — a carrier
disputing a fault, a customer disputing a bill, a colleague six months from now
who does not remember any of this.

That reader asks four different questions, and each one wants a different
artifact. Sending a pcap answers none of them well: it is large, it carries
traffic belonging to everybody else, and it says nothing about what your tap
missed.

## What happened on the call

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./evidence/ --no-cli-print
```

One container per matching dialog, in the format
[`draft-ietf-vcon-vcon-core`](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/)
defines, carrying the parties, the timing and the full message trace. The
selector is the same filter language `--filter` speaks, so the policy is yours
rather than an enumeration of the cases somebody thought of.

Both write paths stage under a dot-prefixed sibling, flush, rename, and sync the
directory, so a bridge polling that spool never sees a half-written container
and a crash mid-write does not destroy the previous one.

## Whether the container is the one you sent

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./evidence/ --vcon-digest > ./evidence/SHA256SUMS
```

`--vcon-digest` prints `<sha256>  <filename>` on stdout while progress stays on
stderr, in `sha256sum`'s own format, so the redirect above produces a file the
standard tool reads with no glue. Run the check from inside the export
directory, because the file names each container relative to itself:

```bash
sha256sum -c SHA256SUMS
```

```text
1-1968_192.0.2.20-cdd887baa4507e9a.vcon.json: OK
```

That is a digest and deliberately NOT a signature, and the reason is worth
understanding before somebody asks for one. A signature over the bytes sipnab
emits could never verify against the object a store holds, because a conserver
adds fields on ingest — so the signature would fail for the ordinary reason and
tell the operator nothing. A digest makes a smaller and honest claim: this is
what sipnab wrote, at this path, at this moment. It says nothing about the
conversation and nothing about what a store did afterwards. What it buys is a
way to bind your emission to the store's own ledger entry out of band, so that
"is the container you have the one we sent?" has an answer neither side has to
take on faith.

## What the capture missed

This is the artifact that separates evidence from a claim. vCon has no field
meaning "this record is incomplete" — `dialog.type: "incomplete"` accuses the
CALL of not completing, which is a statement about the traffic rather than about
the tap. So sipnab carries the caveat in the analysis object and in a
`sipnab-capture-completeness` attachment, both built from one value so the two
cannot disagree:

```jsonc
"capture_completeness": {
  "frames_read": 852,
  "undecodable_frames": 0,
  "sip_discarded_by_port_gate": 0,
  "sip_discarded_by_websocket_gate": 0,
  "messages_evicted": 0,
  "dialogs_rotated": 0,
  "dialogs_refused": 0,
  "headers_dropped_oversize": 0,
  "blind_spots": [],
  "media": "not-considered",
  "node": "capture-01",
  "sipnab_version": "0.5.142"
}
```

Read `media` first. It takes one of four values — carried, refused-over-budget,
none-decodable, or not-considered — and the distinction is the whole point: an
absent `recording` object never has to read as a call that had no audio. The
budget behind `refused-over-budget` has [a note of its
own](@/notes/keep-the-audio-your-store-will-not-take.md).

The block also renders as prose, which is what a non-technical reader actually
reads:

```text
sipnab OBSERVED this dialog and took no part in it: the parties below are what
the From and To headers said, not identities anyone established, and nothing
here is signed. This container carries SIGNALING ONLY — no media, and no
reference to media held elsewhere. That is a fact about this EXPORT, not about
the call: nothing here says whether the conversation carried audio. sipnab read
852 frame(s) for this capture. No omissions recorded: every message sipnab held
for this dialog is in this container.
```

Note the sentence in the middle. A signaling-only container states that it is
signaling-only, so nobody can read the missing audio as a silent call.

## Which command produced it

A report says what sipnab concluded and nothing says which invocation produced
it — which capture, which filter, which port range:

```bash
sipnab -N -I capture.pcap --report --run-provenance-file /var/log/sipnab/runs.jsonl
```

One JSON line per run, appended, created mode 0600 because argv holds capture
paths and a path holds a customer name:

```jsonc
{ "record": "run", "seq": 1,
  "argv": ["sipnab", "-N", "-I", "capture.pcap", "--report"],
  "cwd": "/srv/captures", "user": "voip", "uid": 1000,
  "started": "2026-09-02T02:03:30.547317594+00:00",
  "version": "0.5.142 features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon",
  "capture": { "node": "capture-01", "instance": "27f4618d15ea9d4509f3e-1" } }
```

The `capture.instance` is the same string every MCP and REST answer carries, so
an artifact joins back to the command that made it. A record sipnab cannot
write stops the run, before it has read a single packet. A best-effort line
would be worse than none, because its absence would mean either "not enabled"
or "the disk was full" and nobody could tell which.

## Validate before you send

A store that refuses a container reports the refusal to whoever POSTed it, never
to whoever built it. Check first:

```jsonc
// validate_vcon { "call_id": "..." }
{ "verdict": "valid", "errors": [], "deviations": [], "explanations": [],
  "schema_id": "https://ietf.org/vcon/schemas/unsigned-vcon.json" }
```

Three verdicts rather than two. `valid-except-documented-deviation` means every
finding is a shape sipnab emits on purpose that the schema rejects, with
`deviations` naming each and `explanations` saying why. Folding that into a
clean pass would teach a producer that the deviation is fine in general, and
some of those shapes really are defects when another producer emits them.

## The claim sipnab refuses to make

Every party in the container carries `validation: "none"`, and there is no
signature anywhere. That is not an omission. sipnab watched packets go past a
tap: it did not place the call, record it, or obtain anyone's permission to keep
it. A `From` header is what the sender chose to write, not an identity anyone
established, and a container asserting otherwise would be the one field in the
evidence that nothing measured.

sipnab's own party in the array carries `"role": "observer"` for the same
reason.

That restraint is what makes the rest of the container worth something. A reader
who finds one over-claim in an artifact discounts all of it, and an observer
that never claims more than it saw gives them nothing to discount.

## The set

Send the containers, the `SHA256SUMS` beside them, and the provenance line for
the run that made them. Between them they answer what happened, whether the
bytes are yours, what the tap could not see, and which command produced the lot.
If the containers have to leave your organization,
[redact them first](@/notes/share-the-capture-not-the-customer.md).
