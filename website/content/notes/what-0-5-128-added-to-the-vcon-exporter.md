+++
title = "vCon exporter additions in sipnab 0.5.128"
date = 2026-08-27
updated = 2026-10-11
description = "The fields, transfer records, flags and error format that sipnab 0.5.128 added to its vCon export and REST API, what each one is for, and the two that 0.5.208 changed."

[extra]
kind = "feature"
+++

## In short

A vCon is a standard file format for describing one conversation. It says:

- who took part,
- what they said or what a recorder captured,
- what analysis found.

sipnab can write one vCon file per call it captured. Release 0.5.128 added:

- more caller and call details to those files,
- a record of call transfers,
- three new options,
- a structured error format for sipnab's REST API,
- a safer way of writing files for another program to pick up.

Release 0.5.208 revised two of those changes. It follows a newer version of
the vCon draft standard. This page describes the current behavior.

## Who this is for

Anyone who feeds sipnab's vCon files into a vCon store or another program.
They need to know what each field means.

## What it does

### New fields in each container

A container is one vCon file. 0.5.128 added these fields:

- **`subject`** names the call as `SIP call <Call-ID>`.
  - The Call-ID is the identifier SIP gives the call.
  - It holds nothing else.
- **`parties[].name`** carries the display name from the `From` or `To`
  header.
  - Every party also carries `validation: "none"`.
  - sipnab copies what the message said. It checks no identity.
  - In `tests/pcap-samples/sip-rtp-g711.pcap` the caller's `From` header
    reads `"PCMU/8000" <sip:sipp@10.0.2.20:5060>`.
  - So the caller's `name` is `PCMU/8000`. That is a codec name, not a
    person.
- **`parties[].stir`**, on the caller only, carries the PASSporT from an
  observed `Identity` header ([RFC 8224](https://www.rfc-editor.org/rfc/rfc8224.html)).
  - The PASSporT is the signed token that STIR/SHAKEN caller authentication
    uses.
  - sipnab keeps the token. It drops the header's `info`, `alg` and `ppt`
    parameters.
  - It checks only that the token has three non-empty dot-separated parts.
  - It fetches no certificate and verifies no signature.
- **`dialog[].session_id`** carries the `Session-ID` header pair
  ([RFC 7989](https://www.rfc-editor.org/rfc/rfc7989.html)).
  - That is an identifier that stays the same on both sides of a B2BUA (a
    server that splits a call into two legs with different Call-IDs).
  - sipnab leaves out a half that is `nil` or not a UUID.

### Transfer records

The capture may hold a REFER (the SIP request that transfers a call). Then the
container gains a Dialog Object of type `transfer`.

- It names these as positions in the `parties` list:
  - the `transferor` (who sent the REFER),
  - the `transferee` (the party the transfer moves),
  - the `transfer_target` (the party the `Refer-To` header names).
- It names `original` as the position of the call the transfer happened in.
- sipnab adds the `Refer-To` party to the list so it has a position.

A `Replaces` parameter in the `Refer-To` address identifies an attended
transfer.

- An attended transfer also names a `consultation`.
  - That is the position of a placeholder Dialog Object for the consultation
    call.
  - This capture did not see that call.
- A blind transfer has no `consultation`.

In 0.5.128 that placeholder was an empty object, `{}`.

- Since 0.5.208 it is `{"type": "recording"}`.
- draft-ietf-vcon-vcon-core-04 requires a `type` on every Dialog Object.

### The `type` of a call with no audio

Before 0.5.128, sipnab gave a Dialog Object with no audio the type
`incomplete`.

- The draft reserves that value for a call whose setup failed.
- So every container for an answered call captured without audio reported a
  setup failure.
- In 0.5.128 such an object named no `type` at all.
- Since 0.5.208 it is `"type": "recording"` with no `body` or `url`.
- `incomplete` appears only when sipnab saw a final failure response.
  - Then `disposition` gives the reason.

### New flags

- **`--vcon-max-inline-media <MIB>`** sets the largest audio file a container
  may carry inline, in MiB (default 5).
  - `0` refuses every inline body without turning the export off.
- **`--content-deny-tombstone`** works with `--content-deny-header <NAME>`.
  - A call carrying the named header produces no container by default.
  - With this option it produces an identity-only container.
    - Its `redacted` object reads `{"type": "content-withheld"}`.
    - It has no message trace, no audio and no bodies.
  - It is off by default. Such a container shows that the call took place.
- **`--vcon-digest`** prints a SHA-256 checksum and file name for each
  container written.
  - It uses the format `sha256sum -c` reads.
  - So a later reader can confirm a file is the one sipnab wrote.

### REST error format

sipnab's REST API answers an error with an
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) problem document.

- Its content type is `application/problem+json`.
- It holds `type`, `title`, `status` and sometimes `detail`.
- Before 0.5.128 an error was a status code with no body.
- sipnab builds the `type` URI from the status code alone.
  - An example is `https://sipnab.com/problems/not-found` for 404.
  - So the same kind of error has the same `type` on every route.
- `detail`, when present, says what happened.

### Safer spool writes

`--export-vcon-dir` writes containers to a directory (the spool) that another
program reads. Each file is now:

- written under a temporary name beginning with a dot,
- flushed to disk,
- renamed to its final name.

The directory is then flushed too.

- A reader never sees a partly written file.
- A failed write does not destroy an earlier container.
- The
  [spool contract](@/docs/vcon.md#the-spool-contract-for-a-bridge-that-consumes-it)
  describes the rules a reading program can rely on.

## Example run

Run these from the root of a sipnab checkout. `jq` prints the fields
discussed above.

Export one call to a file:

```bash
sipnab -N --quiet --no-cli-print -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon 1-1966@10.0.2.20 --vcon-out call.vcon.json
```

Read the new fields:

```bash
jq '{subject, caller: .parties[0].name, callee: .parties[1].name, validation: ([.parties[].validation] | unique), dialog_types: [.dialog[].type]}' call.vcon.json
```

```text
{
  "subject": "SIP call 1-1966@10.0.2.20",
  "caller": "PCMU/8000",
  "callee": "test",
  "validation": [
    "none"
  ],
  "dialog_types": [
    "recording"
  ]
}
```

The capture holds the call's audio packets.

- But this run kept no audio (`--retain-audio` was not given).
- So the Dialog Object is the `recording` placeholder with no content.

Write every call that has an INVITE to a spool directory. Record a checksum
for each file.

- `--no-cli-print` keeps sipnab's per-message output off standard output.
- So the checksum file holds only checksum lines:

```bash
sipnab -N --quiet --no-cli-print -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when "method == 'INVITE'" --export-vcon-dir spool --vcon-digest > SHA256SUMS
```

```text
Wrote 2 vCon container(s) to 'spool'.
```

The checksum file names each container without its directory. So check it
from inside the spool:

```bash
cd spool
```

```bash
sha256sum -c ../SHA256SUMS
```

```text
1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json: OK
1-1968_10.0.2.20-cdd887baa4507e9a.vcon.json: OK
```

## Limits

- The capture in the example carries no `Identity` header, no `Session-ID`
  header and no REFER.
  - So the example does not show `stir`, `session_id` or a transfer record.
- sipnab copies `stir` and does not verify it.
  - The consumer must check whether the caller's identity is genuine.
- A transfer record describes the REFER sipnab saw.
  - A placeholder stands for the consultation call of an attended transfer.
  - sipnab holds none of its content.
- A checksum describes the bytes sipnab wrote.
  - A store that adds fields when it receives a container holds different
    bytes.
  - So the checksum confirms what sipnab sent, not what the store kept.

## Terms used here

- **vCon**: a standard format, in draft at the IETF, for recording one
  conversation and what a system learned about it.
- **Container**: one vCon file.
- **Dialog Object**: the part of a vCon that describes one call or recording.
- **Party**: one participant listed in a vCon.
- **SIP**: the protocol phones and servers use to set up and end calls.
- **Call-ID**: the identifier SIP gives each call.
- **REFER**: the SIP request that asks a phone to transfer a call.
- **B2BUA**: back-to-back user agent, a server that splits one call into two
  legs.
- **PASSporT / STIR/SHAKEN**: a signed token that states who placed a call,
  and the framework carriers use to sign and check it.
- **REST API**: sipnab's HTTP interface, started with `--api`.
- **Spool**: a directory where one program leaves files for another to pick
  up.
- **SHA-256 checksum**: a fixed-length fingerprint of a file's bytes. Any
  change to the file changes it.

## Related guides

- [Produce one](@/docs/vcon.md#produce-one) and
  [The spool contract, for a bridge that consumes it](@/docs/vcon.md#the-spool-contract-for-a-bridge-that-consumes-it)
  in the vCon guide.
- [The container cannot say "this is an incomplete record", so sipnab says it twice](@/docs/vcon.md#the-container-cannot-say-this-is-an-incomplete-record-so-sipnab-says-it-twice),
  for how sipnab chooses a Dialog Object's `type`.
- [When a container is missing on purpose](@/docs/vcon.md#when-a-container-is-missing-on-purpose),
  for `--content-deny-header` and `--content-deny-tombstone`.
- [What this does not do](@/docs/vcon.md#what-this-does-not-do), for
  `--vcon-max-inline-media`.
- [Deliver the spool to a store](@/docs/vcon.md#deliver-the-spool-to-a-store),
  for sipnab's own forwarder.
