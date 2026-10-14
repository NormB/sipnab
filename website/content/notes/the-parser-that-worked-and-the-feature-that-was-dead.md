+++
title = "SIPREC recording metadata: who is on a recorded call"
date = 2026-09-05
updated = 2026-10-11
description = "How sipnab reads the participant and stream list a call recorder sends, where it shows that list, and why it was empty on real captures before 0.5.151."

[extra]
kind = "feature"
+++

## In short

A phone system may record a call. Then the recording equipment sends the
recording server a short description of the call. It says:

- who the parties are,
- which audio or video stream belongs to which party.

sipnab reads that description from a capture. It shows it in:

- its report,
- its JSON output,
- its REST API,
- its MCP server,
- the call-flow view of its terminal interface.

Before version 0.5.151 sipnab stored nothing from that description on real
captures. It displayed it nowhere. This note says what it shows now and what
was wrong before.

## Who this is for

Anyone who captures traffic from a network that records calls with SIPREC.
They need to know, from the capture alone:

- who was on a recording,
- which recorded stream is whose.

## What it does

SIPREC (Session Recording Protocol, [RFC 7866](https://www.rfc-editor.org/rfc/rfc7866.html))
is a standard. With it, a session recording client sends a call to a session
recording server (SRS).

- The client is the SRC. Examples are an SBC or OpenSIPS's `siprec` module.
- The SRC opens the recording with a SIP INVITE. That is the message that
  starts a call.
- That INVITE carries an `application/rs-metadata+xml` part. It is an XML
  document that lists:

  - the recording session and its mode (`<datamode>`, for example
    `complete`);
  - each participant, with:
    - an address of record (AOR, the party's SIP address),
    - a display name when the SRC has one;
  - each recorded stream, with a label.
    - The label names the SDP `m=` line that the SRC copied the stream from.
    - That line is in the call's media description.
  - which participant sends each stream, in `<participantstreamassoc>`
    blocks.
    - A `<send>` entry there means the participant sends that stream.
    - A `<recv>` entry means the participant only receives it.

sipnab reads this part from the captured INVITE. It stores it on the call.

- It does not act as an SRC or an SRS.
- It does not take part in the recording.

## How to turn it on

It needs no option. Any run that reads SIP sees the metadata when the
recording INVITE is in the capture. It appears in:

- `--report`, as a `SIPREC recording` block under the call table;
- `--json-dialogs` and the REST API (`GET /v1/dialogs/:call_id`), as a
  `siprec` object on the dialog.
  - A call with no SIPREC metadata has no `siprec` object;
- the MCP tool `siprec_metadata`, which takes a `call_id`.
  - It answers `recorded: true` with the same object.
  - Or it answers `recorded: false` with a reason;
- the call-flow ladder in the terminal interface, as lines under the recording
  INVITE.

## Example

The repository holds one recording INVITE as written by OpenSIPS:
`tests/pcap-samples/siprec-opensips-invite.pcap`. The report shows:

- the participants,
- which of them sends each stream.

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

- Alice sends two streams, labels 0 and 1.
  - They are the audio and the video `m=` lines of the recording INVITE.
- Bob sends label 2.
- Bob does not have a display name. So sipnab prints none.

The same data as JSON:

```bash
sipnab -N -I tests/pcap-samples/siprec-opensips-invite.pcap --json-dialogs --no-cli-print
```

```text
{"call_id":"4f1c0a2e-siprec@172.28.0.31","diagnosis":{"hints":[],"nat_mismatch":false,"no_media":false,"one_way_audio":false,"private_media_address":false},"duration_sec":0.0,"frame":"tests/pcap-samples/siprec-opensips-invite.pcap#0@c7428c303b29281f","input_origin":"wire","method":"INVITE","msg_count":1,"schema_version":1,"sdp_timeline":[],"siprec":{"mode":"complete","participants":[{"aor":"sip:alice@example.invalid","name":"Alice","participant_id":"9b2d1f00"},{"aor":"sip:bob@example.invalid","participant_id":"c7e40a13"}],"session_id":"4f1c0a2e","streams":[{"label":"0","participant_id":"9b2d1f00","stream_id":"1a2b3c4d"},{"label":"1","participant_id":"9b2d1f00","stream_id":"2b3c4d5e"},{"label":"2","participant_id":"c7e40a13","stream_id":"3c4d5e6f"}]},"state":"Trying","streams":[],"timing":{"retransmits":0}}
```

## Limits

- The metadata travels on the INVITE that opens the recording.
  - A capture that starts after that INVITE does not contain it.
  - Then sipnab cannot show it.
- `recorded: false` from the MCP tool means no SIPREC metadata reached the
  capture point.
  - It does not mean the call was not recorded.
  - A recorder signaling on a path the capture cannot see looks the same.
- sipnab reads SIPREC. It is not an SRC or an SRS.

## What was wrong before 0.5.151

sipnab has had a SIPREC reader since April 2026. Its unit tests passed. Unit
tests are small automated tests of one function.

- On real captures the participant and stream data never appeared.
- Three faults caused that.
- Version 0.5.151 (2026-09-05) fixed all three:
  - **sipnab read the recording mode from the wrong element.**
    - It looked for `<mode>`.
    - RFC 7866 and OpenSIPS both use `<datamode>`.
    - So the mode was empty for every call OpenSIPS recorded.
    - sipnab now reads `<datamode>`. It keeps `<mode>` as a fallback.
  - **sipnab read stream ownership from the wrong place.**
    - It looked for the owner inside each `<stream>` element.
    - OpenSIPS writes it only in `<participantstreamassoc>`.
    - So every stream showed no owner.
    - sipnab now reads the `<send>` entries there.
  - **The INVITE that creates a call skipped the reader.**
    - sipnab's call store has three code paths that apply what a message adds
      to a call:
      - one for a call it already holds,
      - one that creates a new call,
      - one that re-applies messages after sipnab merges two records of the
        same call.
    - Two of them ran the SIPREC reader. The path that creates a call did
      not.
    - The recording INVITE is the first message of the recording call.
    - So it is the message that creates the call record. The reader never ran
      on it.
    - All three paths now call one shared function.

The first two faults were not caught because of the unit tests' sample.

- The tests used a sample document written by hand.
- Its layout differed from the one OpenSIPS writes.
- New tests use the layout from OpenSIPS's source file
  `modules/siprec/siprec_body.c`.

The third fault was outside the reader.

- So no test of the reader alone could find it.
- Reading a capture through the full program found it.

Before 0.5.151 no report, API or tool displayed the stored metadata. So the
empty field was not visible to users. The same release added the report,
REST, MCP and ladder output listed above.

## Terms used here

- **SIP**: the signaling protocol that sets up and ends phone calls.
- **INVITE**: the SIP message that starts a call.
- **SIPREC**: the standard for sending a call to a recording server, defined
  in RFC 7866.
- **SRC / SRS**: session recording client and session recording server. The
  client is the equipment that copies the call. The server is the equipment
  that stores it.
- **SDP**: the part of a SIP message that describes the media streams. Each
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

- [See who is on a recorded call](@/docs/cookbook.md#see-who-is-on-a-recorded-call)
- [The `siprec_metadata` MCP tool](@/docs/mcp-tools-vcon.md#siprec-metadata)
- [Glossary: SIPREC, SRC and SRS](@/docs/glossary.md#siprec-src-and-srs)
- [REST API: `GET /v1/dialogs/:call_id`](@/docs/api.md#get-v1-dialogs-call-id)
