+++
title = "vCon exports before 0.5.128 described answered calls as failed setups"
date = 2026-08-27
updated = 2026-10-11
description = "From 0.5.125 to 0.5.127, sipnab gave every vCon record of an answered call without audio the type that means the call was never set up; this explains the cause, the two later changes, and how to check the current behavior."

[extra]
kind = "postmortem"
+++

## In short

A vCon is a standard JSON record of one conversation. A Dialog Object
describes each call in it. Its `type` says what kind of content it holds.

- From sipnab 0.5.125 to 0.5.127, every record of a call without saved audio
  used the type `incomplete`.
  - The vCon draft defines that type as a call whose setup failed.
  - So the records showed answered calls as failed ones.
- Since 0.5.128 sipnab uses `incomplete` only when it saw the call fail.
- Since 0.5.208 a call with no saved audio and no observed failure gets the
  type `recording` with no content.

## What happened

sipnab added vCon export (`--export-vcon` and the `export_vcon` MCP tool) in
0.5.125, released 2026-08-25.

- In 0.5.125, 0.5.126 and 0.5.127, the Dialog Object of every exported call
  that carried no audio had `"type":
  "incomplete"`, unconditionally.
- An export carries no audio in two cases:
  - the capture holds only signaling,
  - the run kept no audio payload.
- Each such record of an answered call stated that the call never reached a
  conversation.
- The object also had no `disposition`.
  - That field names why an incomplete call failed.
  - The draft requires it on an `incomplete` object.

A consumer may have read these records beside a switch's call detail record
that showed a connected call. That consumer received two contradicting
accounts of the same call.

## Why it happened

The vCon core draft (`draft-ietf-vcon-vcon-core-03` at the time) defines five
Dialog Object types: `recording`, `recording-set`, `text`, `transfer` and
`incomplete`.

- Four of them describe content the object holds.
- An object for a call with no saved audio holds no content.
- So sipnab used the fifth, `incomplete`.

The same section of the draft defines `incomplete` by what happened to the
call. It does not define it by what the object holds.

- It is a call that "failed to be setup". The 0.5.128 release notes quote this
  from section 4.3.1.
- sipnab chose the type because it was the one type that does not describe
  content.
- That choice also stated that the call had failed.

## What changed

**0.5.128 (2026-08-27).** sipnab decides the type and the disposition together:

- A final response that sipnab saw fail produces `"type": "incomplete"` with
  a `disposition` naming the reason.
- An object with no content and no observed failure got no `type` at all.
  - Draft `-03` allowed a Dialog Object with no parameters. That was for a
    dialog known to have occurred with nothing available about it.
  - The vCon working group had agreed on that shape. The 0.5.128 release notes
    cite the working group's issue #20.
  - The draft's own JSON schema required `type`.
  - So sipnab's copy of the schema carried one recorded deviation.

**0.5.208 (2026-10-09).** sipnab follows `draft-ietf-vcon-vcon-core-04`.

- That draft requires `type` on every Dialog Object.
- It no longer has the sentence that allowed an empty one.
- A call with no saved audio and no observed failure is now
  `"type": "recording"` with no `body`, `url` or `mediatype`.
  - That is the placeholder that section 4.3 of `-04` defines for a dialog
    known to have occurred.
- The vendored schema, `tests/schemas/vcon.schema.json`, is now the working
  group's `-04` file unchanged.
- The local deviation no longer exists.

The current rule, as the [vCon guide](@/docs/vcon.md#read-what-a-container-says-the-capture-missed)
states it:

- An object with audio is `recording`.
- An object with no content and no observed failure is `recording` with no
  content.
- An object with no content and an observed final failure is `incomplete`,
  with the reason in `disposition`.

"No observed failure" includes:

- an answered call,
- a call whose final response the capture did not contain,
- a redirect.

An absent `disposition` does not mean the call succeeded.

A consumer that selects `type == "recording"` must check that `body` or `url`
is present before reading the audio.

- The [vCon guide](@/docs/vcon.md#read-what-a-container-says-the-capture-missed)
  records a case at vcon-server commit `8ffbfcf`.
- There, the `deepgram_link` transcription link reads `dialog["url"]` without
  that check.
- It raises an error on such an object.

## What you can check yourself

The commands run from the root of a sipnab checkout. `jq` prints the
`dialog` array of each container.

Export the two answered calls in a capture. Read only the SIP port, so that
the run captures no audio:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when "response_code == 200" --export-vcon-dir ./answered/ --no-cli-print --quiet 'udp port 5060'
```

```text
Wrote 2 vCon container(s) to './answered/'.
```

```bash
jq -c '.dialog' answered/*.vcon.json
```

```text
[{"type":"recording","sip_call_id":"1-1966@10.0.2.20","sip_from_tag":"1","sip_to_tag":"QvN92t713vSZK","start":"2016-11-26T14:52:59.666393+00:00"}]
[{"type":"recording","sip_call_id":"1-1968@10.0.2.20","sip_from_tag":"1","sip_to_tag":"r5e24Nr505FjF","start":"2016-11-26T14:53:08.286194+00:00"}]
```

Both calls have the type `recording`, with no content and no `disposition`.

Export a call that failed with a `488 Not Acceptable Here` response:

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./failed/ --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './failed/'.
```

```bash
jq -c '.dialog' failed/*.vcon.json
```

```text
[{"type":"incomplete","disposition":"failed","sip_call_id":"codec-reject-synth","sip_from_tag":"tag-caller-488","sip_to_tag":"tag-auth-488","start":"2019-08-27T17:26:48.834678+00:00"}]
```

The failed call has the type `incomplete`, with `"disposition": "failed"`.

## Terms used here

- **vCon**: a JSON container format for one conversation, defined by an IETF
  working group draft.
- **Dialog Object**: the part of a vCon that describes one call or recording.
- **Draft**: an IETF Internet-Draft, a specification still in progress.
- **Schema**: a machine-readable description of a valid document, used to
  validate it.
- **Disposition**: the vCon field that names why an incomplete call failed.
  Examples are `failed` and `busy`.
- **Signaling**: the SIP messages that set up and end a call, as opposed to
  the audio.
- **Call detail record**: the per-call record a switch writes for billing and
  reporting.
- **MCP**: the Model Context Protocol, the interface sipnab offers to AI
  agents.

## Related guides

- [vCon: Read what a container says the capture missed](@/docs/vcon.md#read-what-a-container-says-the-capture-missed)
- [vCon: Read what came out](@/docs/vcon.md#read-what-came-out)
- [vCon: Someone handed you a sipnab vCon, what may you conclude?](@/docs/vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
