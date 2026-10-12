+++
title = "SIPREC recording metadata: who is on a recorded call"
date = 2026-09-05
updated = 2026-10-11
description = "How sipnab reads the participant and stream list a call recorder sends, where it shows that list, and why it was empty on real captures before 0.5.151."

[extra]
kind = "feature"
+++

## In short

When a phone system records a call, the recording equipment sends the
recording server a short description of the call: who the parties are and
which audio or video stream belongs to which party. sipnab reads that
description from a capture and shows it in its report, its JSON output, its
REST API, its MCP server and the call-flow view of its terminal interface.
Before version 0.5.151 sipnab stored nothing from that description on real
captures and displayed it nowhere. This note says what it shows now and what was wrong before.

## Who this is for

Anyone who captures traffic from a network that records calls with SIPREC
and needs to know, from the capture alone, who was on a recording and which
recorded stream is whose.

## What it does

SIPREC (Session Recording Protocol, [RFC 7866](https://www.rfc-editor.org/rfc/rfc7866))
is the standard way for a session recording client (SRC, for example an SBC or
OpenSIPS's `siprec` module) to send a call to a session recording server (SRS).
The SRC opens the recording with a SIP INVITE, the message that starts a call.
That INVITE carries an `application/rs-metadata+xml` part, an XML document
that lists:

- the recording session and its mode (`<datamode>`, for example `complete`);
- each participant, with an address of record (AOR, the party's SIP address)
  and a display name when the SRC has one;
- each recorded stream, with a label naming the SDP `m=` line (the line in the
  call's media description) that the SRC copied it from;
- which participant sends each stream, in `<participantstreamassoc>` blocks.
  A `<send>` entry there means the participant sends that stream; a `<recv>`
  entry means the participant only receives it.

sipnab reads this part from the captured INVITE and stores it on the call. It
does not act as an SRC or an SRS and does not take part in the recording.

## How to turn it on

It needs no option. Any run that reads SIP sees the metadata when the
recording INVITE is in the capture. It appears in:

- `--report`, as a `SIPREC recording` block under the call table;
- `--json-dialogs` and the REST API (`GET /v1/dialogs/:call_id`), as a
  `siprec` object on the dialog. A call with no SIPREC metadata has no
  `siprec` object;
- the MCP tool `siprec_metadata`, which takes a `call_id` and answers
  `recorded: true` with the same object, or `recorded: false` with a reason;
- the call-flow ladder in the terminal interface, as lines under the recording
  INVITE.

## Example

The repository holds one recording INVITE as written by OpenSIPS:
`tests/pcap-samples/siprec-opensips-invite.pcap`. The report shows the
participants and which of them sends each stream:

```bash
sipnab -N -I tests/pcap-samples/siprec-opensips-invite.pcap --report --no-cli-print
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags            
-------------------------------------------------------------------------------------------------------------------------
4f1c0a2e-siprec@172.28.0.31      -              srs            Trying       -      0s         1      -        -               

SIPREC recording (4f1c0a2e-siprec@172.28.0.31): session 4f1c0a2e, complete
  participant sip:alice@example.invalid (Alice)
  participant sip:bob@example.invalid
  stream label 0 -> sip:alice@example.invalid
  stream label 1 -> sip:alice@example.invalid
  stream label 2 -> sip:bob@example.invalid
```

Alice sends two streams, labels 0 and 1 (the audio and the video `m=` lines of
the recording INVITE). Bob sends label 2. Bob does not have a display name, so
sipnab prints none.

The same data as JSON:

```bash
sipnab -N -I tests/pcap-samples/siprec-opensips-invite.pcap --json-dialogs --no-cli-print
```

```text
{"call_id":"4f1c0a2e-siprec@172.28.0.31","diagnosis":{"hints":[],"nat_mismatch":false,"no_media":false,"one_way_audio":false,"private_media_address":false},"duration_sec":0.0,"frame":"tests/pcap-samples/siprec-opensips-invite.pcap#0@c7428c303b29281f","input_origin":"wire","method":"INVITE","msg_count":1,"schema_version":1,"sdp_timeline":[],"siprec":{"mode":"complete","participants":[{"aor":"sip:alice@example.invalid","name":"Alice","participant_id":"9b2d1f00"},{"aor":"sip:bob@example.invalid","participant_id":"c7e40a13"}],"session_id":"4f1c0a2e","streams":[{"label":"0","participant_id":"9b2d1f00","stream_id":"1a2b3c4d"},{"label":"1","participant_id":"9b2d1f00","stream_id":"2b3c4d5e"},{"label":"2","participant_id":"c7e40a13","stream_id":"3c4d5e6f"}]},"state":"Trying","streams":[],"timing":{"retransmits":0}}
```

## Limits

- The metadata travels on the INVITE that opens the recording. A capture that
  starts after that INVITE does not contain it, and sipnab cannot show it.
- `recorded: false` from the MCP tool means no SIPREC metadata reached the
  capture point. It does not mean the call was not recorded: a recorder
  signaling on a path the capture cannot see looks the same.
- sipnab reads SIPREC. It is not an SRC or an SRS.

## What was wrong before 0.5.151

sipnab has had a SIPREC reader since April 2026, with unit tests (small automated
tests of one function) that passed. On real captures the participant and
stream data never appeared. Three faults caused that, and version 0.5.151
(2026-09-05) fixed all three:

1. **sipnab read the recording mode from the wrong element.** It looked for
   `<mode>`. RFC 7866 and OpenSIPS both use `<datamode>`, so the mode was
   empty for every call OpenSIPS recorded. sipnab now reads `<datamode>` and keeps `<mode>` as a
   fallback.
2. **sipnab read stream ownership from the wrong place.** It looked for the
   owner inside each `<stream>` element. OpenSIPS writes it only in
   `<participantstreamassoc>`, so every stream showed no owner. sipnab now
   reads the `<send>` entries there.
3. **The INVITE that creates a call skipped the reader.** sipnab's call store
   has three code paths that apply what a message adds to a call: one for a
   call it already holds, one that creates a new call, and one that re-applies
   messages after sipnab merges two records of the same call. Two of them ran
   the SIPREC reader and the path that creates a call did not. The recording
   INVITE is the first message of the recording call, so it is the message
   that creates the call record, and the reader never ran on it. All three paths now call one shared function.

The first two faults were not caught because the unit tests used a sample
document written by hand, with a different layout from the one OpenSIPS
writes. New tests use the layout from OpenSIPS's source file
`modules/siprec/siprec_body.c`. The third fault was outside the reader, so no
test of the reader alone could find it. Reading a capture through the full
program found it. Before 0.5.151 no report, API or tool displayed the
stored metadata, so the empty field was not visible to users. The same release
added the report, REST, MCP and ladder output listed above.

## Terms used here

- **SIP**: the signaling protocol that sets up and ends phone calls.
- **INVITE**: the SIP message that starts a call.
- **SIPREC**: the standard for sending a call to a recording server, defined
  in RFC 7866.
- **SRC / SRS**: session recording client (the equipment that copies the call)
  and session recording server (the equipment that stores it).
- **SDP**: the part of a SIP message that describes the media streams; each
  `m=` line is one stream.
- **AOR**: address of record, the SIP address that identifies a party.
- **Dialog**: sipnab's record of one call.
- **XML**: a text format of nested, named elements.
- **JSON**: a text format for structured data that programs read.
- **REST API**: sipnab's HTTP interface for programs.
- **MCP**: Model Context Protocol, the interface sipnab offers to AI agents.
- **Ladder**: the call-flow diagram in sipnab's terminal interface.
- **pcap**: a file of captured network packets.
- **Unit test**: an automated test that checks one function on its own.

## Related guides

- [See who is on a recorded call](@/docs/cookbook.md#60-see-who-is-on-a-recorded-call)
- [The `siprec_metadata` MCP tool](@/docs/mcp-tools.md#siprec-metadata)
- [Glossary: SIPREC, SRC and SRS](@/docs/glossary.md#siprec-src-and-srs)
- [REST API: `GET /v1/dialogs/:call_id`](@/docs/api.md#get-v1-dialogs-call-id)
