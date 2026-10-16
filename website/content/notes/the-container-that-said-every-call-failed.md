+++
title = "Tell an answered call from a failed one in a sipnab vCon export"
date = 2026-08-27
updated = 2026-10-16
description = "Export calls as vCon containers, read the type and disposition of each Dialog Object, and tell an answered call from a call that failed and from one the capture cannot settle."

[extra]
kind = "howto"
+++

## In short

A vCon is a standard JSON record of one conversation. Each call in it is a
Dialog Object, and two of its fields say what sipnab saw:

- `"type": "incomplete"` with a `disposition` means sipnab saw the call fail,
  and the `disposition` names how.
- `"type": "recording"` with no `body` and no `url` means the container holds
  no audio and sipnab saw no failure. Either the callee answered, or the
  capture does not show how the call ended.
- `"type": "recording"` with a `body` or a `url` carries the call's audio.

This page exports both kinds from captures in the sipnab repository and reads
the two fields.

## Who this is for

Anyone who receives vCon containers from sipnab and needs to sort answered
calls from failed ones, including a program that reads the containers.

## Before you start

- A sipnab built with the `vcon` feature. `sipnab --version` lists the
  features of a build.
- `jq`, to read the JSON.
- The commands run from the root of a sipnab checkout.

## Export two answered calls

Read only the SIP port, so the run keeps no audio, and write a container for
each call answered with `200`:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when "response_code == 200" --export-vcon-dir ./answered/ --no-cli-print --quiet 'udp port 5060'
```

```text
Wrote 2 vCon container(s) to './answered/'.
```

Print the type, the disposition, and whether each Dialog Object holds
content:

```bash
jq -c '.dialog[] | {type, disposition, has_content: (has("body") or has("url"))}' answered/*.vcon.json
```

```text
{"type":"recording","disposition":null,"has_content":false}
{"type":"recording","disposition":null,"has_content":false}
```

Both are `recording` with no content and no `disposition`.

## Export a failed call

This capture holds one call that failed with `488 Not Acceptable Here`:

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./failed/ --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './failed/'.
```

```bash
jq -c '.dialog[] | {type, disposition, has_content: (has("body") or has("url"))}' failed/*.vcon.json
```

```text
{"type":"incomplete","disposition":"failed","has_content":false}
```

## Read the two fields

| The object holds | `type` | `disposition` |
|---|---|---|
| audio | `recording` | absent |
| no content, no failure seen | `recording`, with no `body` or `url` | absent |
| no content, a final failure seen | `incomplete` | the reason |

The `disposition` values are `busy` (`486`, `600`), `congestion` (`503`),
`no-answer` (`408`, `480`, or `487` after a CANCEL in the capture), and
`failed` for any other final failure.

"No failure seen" covers an answered call, a redirect, and a call whose final
response the capture does not contain. An absent `disposition` does not mean
the call succeeded.

## If you read the audio from a container

Select on content, not on type. A `recording` object with no `body` and no
`url` carries no audio, and its `duration` is not the length of a recording.
Check that `body` or `url` is present before you read either.

## Terms used here

- **vCon**: a JSON container format for one conversation, defined by an IETF
  working group draft.
- **Dialog Object**: the part of a vCon that describes one call or recording.
- **Disposition**: the vCon field that names why an incomplete call failed.
- **Final response**: the SIP response that ends a call attempt, such as
  `200 OK` or `486 Busy Here`.
- **Signaling**: the SIP messages that set up and end a call, as opposed to
  the audio.
- **`jq`**: a command-line program that selects fields from JSON.

## Related guides

- [vCon: Read what a container says the capture missed](@/docs/vcon.md#read-what-a-container-says-the-capture-missed)
- [vCon: Read what came out](@/docs/vcon.md#read-what-came-out)
- [vCon: Someone handed you a sipnab vCon, what may you conclude?](@/docs/vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
