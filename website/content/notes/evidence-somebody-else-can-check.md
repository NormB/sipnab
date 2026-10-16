+++
title = "Hand over call evidence that another party can check"
date = 2026-09-01
updated = 2026-10-16
description = "Export the disputed calls as vCon containers, add a checksum file and a record of the command, and check each piece before you send it."

[extra]
kind = "howto"
+++

## In short

A carrier or a customer may dispute what happened on a call. Then they need
evidence they can check without trusting you. sipnab can:

- write each disputed call to its own standard record file (a vCon),
- list a checksum for each file, so the receiver can confirm the files were
  not changed,
- record the exact command that produced them.

Each file also states what the capture could not see. So a missing recording
is not read as a silent call.

## Who this is for

Anyone who has found the cause of a call problem in a capture. They now have to
hand the result to a party outside the investigation.

## Before you start

The steps run from the root of a sipnab checkout.

- They read `tests/pcap-samples/sip-488-codec-reject.pcapng`, a capture with
  one failed call.
- The last three steps use `jq`, a command-line JSON reader.
- The output below came from sipnab 0.5.222.

## Steps

- Create the directory that holds the evidence.

```bash
mkdir evidence
```

This prints nothing. The directory has to exist before the export step. The
shell opens the checksum file before sipnab starts.

- Export every failed call, write the checksum file, and record the command.

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./evidence/ --vcon-digest --no-cli-print --run-provenance-file ./evidence/runs.jsonl > ./evidence/SHA256SUMS
```

```text
Wrote 1 vCon container(s) to './evidence/'.
```

What each part does:

- `--export-vcon-when "state == 'Failed'"` writes one container (one vCon
  file) per call that matches the expression.
  - The expression uses the same language as `--filter`.
  - The [filter guide](@/docs/filter-dsl.md) describes it.
- `--export-vcon-dir ./evidence/` is where the containers go. sipnab writes
  each one this way:
  - under a temporary hidden name,
  - then it flushes it to disk,
  - then it renames it.
  - So a program reading the directory never sees a half-written file.
  - A crash during a write leaves the previous file intact.
- `--vcon-digest` prints one line per container to standard output.
  - The format is that of the `sha256sum` tool: the SHA-256 checksum, two
    spaces, the file name.
  - The `>` sends those lines to `SHA256SUMS`.
- `--no-cli-print` stops the per-message listing.
  - `--vcon-digest` turns it on as well.
  - So the checksum lines are the only output on standard output, and
    `SHA256SUMS` holds nothing else.
- `--run-provenance-file ./evidence/runs.jsonl` appends one JSON line saying
  how this run started (see the last step).
- `-q` hides the timestamped log lines. So only the summary line above is
  printed.

The next step:

- Check the container against the vCon schema before you send it.
  - A store that refuses a container reports the refusal to whoever sent it.
    It does not report it to whoever built it.
  - The check is the `validate_vcon` tool of sipnab's MCP server. MCP is the
    interface an AI agent or another program uses to query sipnab.
  - This command starts that server over standard input. It sends the three
    messages a client sends. It exits when the input ends:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_vcon","arguments":{"call_id":"codec-reject-synth"}}}' | sipnab -N -q --mcp -I tests/pcap-samples/sip-488-codec-reject.pcapng
```

```text
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"completions":{},"prompts":{},"resources":{"subscribe":true},"tools":{}},"serverInfo":{"name":"sipnab","version":"0.5.222"},"instructions":"sipnab MCP server — queries captured SIP dialogs, RTP streams, diagnostics and security findings. No tool edits a capture's contents. `open_capture` can change WHICH capture is loaded and stays off unless enabled server-side; every response carries `capture_identity`, so a swap is visible rather than silent. File exports write only under the configured file root, and stopping the server requires an explicit server-side opt-in. This server changes no external system: the tools that would (tfps_ban, tfps_unban) refuse unless the operator enables them with --allow-action. Tools loaded: full."}}
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"call_id\":\"codec-reject-synth\",\"errors\":[],\"schema_id\":\"https://ietf.org/vcon/schemas/unsigned-vcon.json\",\"schema_path\":\"tests/schemas/vcon.schema.json\",\"schema_version\":2,\"source_exhausted\":true,\"source_stopped_early\":false,\"verdict\":\"valid\"}"}],"structuredContent":{"call_id":"codec-reject-synth","errors":[],"schema_id":"https://ietf.org/vcon/schemas/unsigned-vcon.json","schema_path":"tests/schemas/vcon.schema.json","schema_version":2,"source_exhausted":true,"source_stopped_early":false,"verdict":"valid"},"isError":false}}
```

The tool builds the container for that Call-ID from the same capture and
checks it.

`verdict` is `valid` or `invalid`. For `invalid`, `errors` names each value
the schema refused.

- Go into the evidence directory. `SHA256SUMS` names each container by its
  bare file name. So the check that the containers match their checksums runs
  from here.

```bash
cd evidence
```

- Confirm the containers match their checksums. The receiver runs the same
  command on the files you send.

```bash
sha256sum -c SHA256SUMS
```

```text
codec-reject-synth-3513dc650e9bad6e.vcon.json: OK
```

A checksum is not a signature.

- It shows that these bytes are the ones sipnab wrote.
- It does not show who wrote them.
- It says nothing about what a vCon store changes after it receives the file.

sipnab does not sign containers.

- A store adds fields when it takes one in.
- So a signature over sipnab's bytes would fail to verify against the stored
  copy.

Keep `SHA256SUMS`. Then both sides can compare a stored container with what you
sent.

- Read what the capture could not see.
  - The vCon format has no field for "this record is incomplete".
  - So sipnab writes a `capture_completeness` object into the container's
    analysis entry.
  - It writes the same object into an attachment with the purpose
    `sipnab-capture-completeness`.

```bash
jq '.analysis[0].body.capture_completeness | del(.node, .note)' codec-reject-synth-3513dc650e9bad6e.vcon.json
```

```text
{
  "blind_spots": [],
  "call_ended": true,
  "dialogs_refused": 0,
  "dialogs_rotated": 0,
  "dialogs_suppressed_by_deny": 0,
  "frames_read": 13,
  "gate_closed_during_run": false,
  "headers_dropped_oversize": 0,
  "media": "none-decodable",
  "media_note": "No RTP streams to export",
  "messages_evicted": 0,
  "sip_discarded_by_port_gate": 0,
  "sip_discarded_by_websocket_gate": 0,
  "sipnab_version": "0.5.222",
  "undecodable_frames": 0
}
```

The command leaves out two fields:

- `node`, the name of the machine that ran sipnab,
- `note`, the same information written as sentences for a reader who does not
  read JSON.

Read `media` first. It has one of five values:

- `carried`
- `refused-over-budget`
- `none-decodable`
- `not-considered`
- `withheld-by-redaction`

Each one explains why the container does or does not hold audio. So a
container without audio is never read as a call that had none.

The note
[Set the largest audio a vCon container may carry inline](@/notes/keep-the-audio-your-store-will-not-take.md)
covers the audio budget behind `refused-over-budget`. The
[vCon guide](@/docs/vcon.md#read-what-a-container-says-the-capture-missed)
describes every field.

- Check what the container claims about the people on the call.

```bash
jq -c '.parties[] | {validation, role}' codec-reject-synth-3513dc650e9bad6e.vcon.json
```

```text
{"validation":"none","role":null}
{"validation":"none","role":null}
{"validation":"none","role":"observer"}
```

sipnab only watched the packets. A `From` header is what the sender chose to
write. So every party carries `"validation": "none"`. The third party is sipnab
itself, with the role `observer`.

- Read the record of the command that produced the containers.

```bash
jq '{record, seq, argv, version, instance: .capture.instance}' runs.jsonl
```

```text
{
  "record": "run",
  "seq": 1,
  "argv": [
    "sipnab",
    "-N",
    "-q",
    "-I",
    "tests/pcap-samples/sip-488-codec-reject.pcapng",
    "--export-vcon-when",
    "state == 'Failed'",
    "--export-vcon-dir",
    "./evidence/",
    "--vcon-digest",
    "--no-cli-print",
    "--run-provenance-file",
    "./evidence/runs.jsonl"
  ],
  "version": "0.5.222 (16f7b0ea) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,wasm,plugins,bpf,vcon,opus,archive,g729",
  "instance": "11b18b18df002253d62562-1"
}
```

The command selects five of the record's fields. The full line also carries
`cwd`, `user`, `uid`, `pid`, `started`, `ts`, `features` and the rest of
`capture`.

- `instance` is a new value on every run.
- It is the same capture identifier that every MCP and REST answer from that
  run carries.
- sipnab creates the file with mode `0600` (readable only by its owner).
  - The command line holds capture paths.
  - A path can hold a customer name.
- Each run appends one line.

sipnab may not be able to write the record. Then it:

- stops before reading any packet,
- exits with status 2,
- logs an error with this message. This example is for a directory that does
  not exist:

```text
--run-provenance-file /nonexistent/dir/runs.jsonl: No such file or directory (os error 2). sipnab refuses to run without the provenance record it was asked for -- a missing record would otherwise be indistinguishable from a run nobody asked to record
```

## What to send

The `evidence` directory now holds the containers, `SHA256SUMS` and
`runs.jsonl`. Together they:

- say what happened on each call,
- let the receiver confirm the files are the ones you wrote,
- state what the capture missed,
- name the command that produced them.

The containers may leave your organization. Then remove personal data first,
as described in
[Share the capture, not the customer](@/notes/share-the-capture-not-the-customer.md).

## Limits

- A checksum shows the files have not changed. It does not identify who wrote
  them.
- sipnab states no identity it did not establish.
  - sipnab validates no party.
  - The container carries no signature.
  - The
    [vCon guide](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container)
    lists what sipnab leaves out of a container.
- The record and the containers name the machine that ran sipnab as the
  node. `--node-name` sets that name. Without it, sipnab uses the system host
  name.

## Terms used here

- **SIP**: the signaling protocol that sets up, changes and ends a phone call.
- **Dialog**: one SIP call from its first request to its end.
- **Call-ID**: the identifier SIP gives every message of one call.
- **RTP**: the protocol that carries a call's audio.
- **Capture (pcap)**: a file of network packets recorded from a network
  interface.
- **vCon**: a standard JSON format for a record of one conversation. The IETF
  draft draft-ietf-vcon-vcon-core defines it.
- **Container**: one vCon file.
- **Schema**: the machine-readable rules a vCon file must follow.
- **vCon store (conserver)**: a server that receives and keeps vCon files.
- **Checksum (SHA-256 digest)**: a fixed-length value computed from a file's
  bytes. Any change to the file changes it.
- **Signature**: a value that proves who produced a file. sipnab does not
  produce one.
- **Standard output**: the stream a command's results go to. `>` redirects it
  to a file.
- **MCP**: Model Context Protocol, the interface an AI agent or another
  program uses to call sipnab's tools.
- **REST**: sipnab's HTTP API.
- **Provenance record**: the line describing which command produced a result.

## Related guides

- [The spool contract, for a bridge that consumes it](@/docs/vcon.md#the-spool-contract-for-a-bridge-that-consumes-it): the write order and `--vcon-digest`.
- [Read what a container says the capture missed](@/docs/vcon.md#read-what-a-container-says-the-capture-missed): every `capture_completeness` field.
- [Someone handed you a sipnab vCon — what may you conclude?](@/docs/vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude): what the receiver can conclude.
- [What sipnab refuses to put in a container](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container)
- [`validate_vcon`](@/docs/mcp-tools-vcon.md#validate-vcon): the tool's arguments and answers.
- [CLI reference: Output](@/docs/cli.md#output): `--export-vcon-when`, `--export-vcon-dir`, `--vcon-digest`, `--no-cli-print`.
- [CLI reference: Security](@/docs/cli.md#security): `--run-provenance-file`.
