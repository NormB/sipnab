+++
title = "Hand over call evidence that another party can check"
date = 2026-09-01
updated = 2026-10-11
description = "Export the disputed calls as vCon containers, add a checksum file and a record of the command, and check each piece before you send it."

[extra]
kind = "howto"
+++

## In short

When a carrier or a customer disputes what happened on a call, they need
evidence they can check without trusting you. sipnab can write each disputed
call to its own standard record file (a vCon), list a checksum for each file
so the receiver can confirm the files were not changed, and record the exact
command that produced them. Each file also states what the capture could not
see, so a missing recording is not read as a silent call.

## Who this is for

Anyone who has found the cause of a call problem in a capture and now has to
hand the result to a party outside the investigation.

## Before you start

The steps run from the root of a sipnab checkout against
`tests/pcap-samples/sip-488-codec-reject.pcapng`, a capture with one failed
call. Steps 6 to 8 use `jq`, a command-line JSON reader. The output below came
from sipnab 0.5.211.

## Steps

1. Create the directory that holds the evidence.

```bash
mkdir evidence
```

This prints nothing. The directory has to exist before step 2, because the
shell opens the checksum file before sipnab starts.

2. Export every failed call, write the checksum file, and record the command.

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./evidence/ --vcon-digest --no-cli-print --run-provenance-file ./evidence/runs.jsonl > ./evidence/SHA256SUMS
```

```text
Wrote 1 vCon container(s) to './evidence/'.
```

What each part does:

- `--export-vcon-when "state == 'Failed'"` writes one container (one vCon
  file) per call that matches the expression. The expression uses the same
  language as `--filter`, described in the
  [filter guide](@/docs/filter-dsl.md).
- `--export-vcon-dir ./evidence/` is where the containers go. sipnab writes
  each one under a temporary hidden name, flushes it to disk, then renames it,
  so a program reading the directory never sees a half-written file and a
  crash during a write leaves the previous file intact.
- `--vcon-digest` prints one line per container to standard output, in the
  format of the `sha256sum` tool: the SHA-256 checksum, two spaces, the file
  name. The `>` sends those lines to `SHA256SUMS`.
- `--no-cli-print` stops the per-message listing. On 0.5.211 that listing also
  goes to standard output, so without this flag it lands in `SHA256SUMS`, and
  `sha256sum -c` then reports `WARNING: 54 lines are improperly formatted` for
  this capture.
- `--run-provenance-file ./evidence/runs.jsonl` appends one JSON line saying
  how this run started (step 8).
- `-q` hides the timestamped log lines, so only the summary line above is
  printed.

3. Check the container against the vCon schema before you send it. A store
   that refuses a container reports the refusal to whoever sent it, not to
   whoever built it. The check is the `validate_vcon` tool of sipnab's MCP
   server (the interface an AI agent or another program uses to query sipnab).
   This command starts that server over standard input, sends the three
   messages a client sends, and exits when the input ends:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_vcon","arguments":{"call_id":"codec-reject-synth"}}}' | sipnab -N -q --mcp -I tests/pcap-samples/sip-488-codec-reject.pcapng
```

```text
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"completions":{},"prompts":{},"resources":{"subscribe":true},"tools":{}},"serverInfo":{"name":"sipnab","version":"0.5.211"},"instructions":"sipnab MCP server — queries captured SIP dialogs, RTP streams, diagnostics and security findings. No tool edits a capture's contents. `open_capture` can change WHICH capture is loaded and stays off unless enabled server-side; every response carries `capture_identity`, so a swap is visible rather than silent. File exports write only under the configured file root, and stopping the server requires an explicit server-side opt-in. This server changes no external system: the tools that would (tfps_ban, tfps_unban) refuse unless the operator enables them with --allow-action. Tools loaded: full."}}
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"call_id\":\"codec-reject-synth\",\"errors\":[],\"schema_id\":\"https://ietf.org/vcon/schemas/unsigned-vcon.json\",\"schema_path\":\"tests/schemas/vcon.schema.json\",\"schema_version\":2,\"source_exhausted\":true,\"source_stopped_early\":false,\"verdict\":\"valid\"}"}],"structuredContent":{"call_id":"codec-reject-synth","errors":[],"schema_id":"https://ietf.org/vcon/schemas/unsigned-vcon.json","schema_path":"tests/schemas/vcon.schema.json","schema_version":2,"source_exhausted":true,"source_stopped_early":false,"verdict":"valid"},"isError":false}}
```

The tool builds the container for that Call-ID from the same capture and
checks it. `verdict` is `valid` or `invalid`. For `invalid`, `errors` names
each value the schema refused.

4. Go into the evidence directory. `SHA256SUMS` names each container by its
   bare file name, so the check in step 5 runs from here.

```bash
cd evidence
```

5. Confirm the containers match their checksums. The receiver runs the same
   command on the files you send.

```bash
sha256sum -c SHA256SUMS
```

```text
codec-reject-synth-3513dc650e9bad6e.vcon.json: OK
```

A checksum is not a signature: it shows that these bytes are the ones sipnab
wrote, not who wrote them, and says nothing about what a vCon store changes
after it receives the file. sipnab does not sign containers, because a store
adds fields when it takes one in, so a signature over sipnab's bytes would
fail to verify against the stored copy. Keep `SHA256SUMS` so both sides can
compare a stored container with what you sent.

6. Read what the capture could not see. The vCon format has no field for "this
   record is incomplete", so sipnab writes a `capture_completeness` object into
   the container's analysis entry, and the same object into an attachment with
   the purpose `sipnab-capture-completeness`.

```bash
jq '.analysis[0].body | fromjson | .capture_completeness | del(.node, .note)' codec-reject-synth-3513dc650e9bad6e.vcon.json
```

```text
{
  "blind_spots": [],
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
  "sipnab_version": "0.5.211",
  "undecodable_frames": 0
}
```

The command leaves out two fields: `node`, the name of the machine that ran
sipnab, and `note`, the same information written as sentences for a reader
who does not read JSON. Read `media` first. It has one of five values:
`carried`, `refused-over-budget`, `none-decodable`, `not-considered` or
`withheld-by-redaction`. Each one explains why the container does or does not
hold audio, so a container without audio is never read as a call that had
none.

The note
[Set the largest audio a vCon container may carry inline](@/notes/keep-the-audio-your-store-will-not-take.md)
covers the audio budget behind `refused-over-budget`. The
[vCon guide](@/docs/vcon.md#the-container-cannot-say-this-is-an-incomplete-record-so-sipnab-says-it-twice)
describes every field.

7. Check what the container claims about the people on the call.

```bash
jq -c '.parties[] | {validation, role}' codec-reject-synth-3513dc650e9bad6e.vcon.json
```

```text
{"validation":"none","role":null}
{"validation":"none","role":null}
{"validation":"none","role":"observer"}
```

sipnab only watched the packets. A `From` header is what the sender chose to
write, so every party carries `"validation": "none"`. The third party is
sipnab itself, with the role `observer`.

8. Read the record of the command that produced the containers.

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
  "version": "0.5.211 (15e5e7bd) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,archive",
  "instance": "63cd118dda1693a8a6dc1-1"
}
```

The command selects five of the record's fields. The full line also carries
`cwd`, `user`, `uid`, `pid`, `started`, `ts`, `features` and the rest of
`capture`. `instance` is a new value on every run. It is the same capture
identifier that every MCP and REST answer from that run carries. sipnab
creates the file with mode `0600` (readable only by its owner), because the
command line holds capture paths and a path can hold a customer name. Each run
appends one line.

If sipnab cannot write the record, it stops before reading any packet, exits
with status 2, and logs an error with this message (shown here for a
directory that does not exist):

```text
--run-provenance-file /nonexistent/dir/runs.jsonl: No such file or directory (os error 2). sipnab refuses to run without the provenance record it was asked for -- a missing record would otherwise be indistinguishable from a run nobody asked to record
```

## What to send

The `evidence` directory now holds the containers, `SHA256SUMS` and
`runs.jsonl`. Together they say what happened on each call, let the receiver
confirm the files are the ones you wrote, state what the capture missed, and
name the command that produced them. If the containers leave your
organization, remove personal data first, as described in
[Share the capture, not the customer](@/notes/share-the-capture-not-the-customer.md).

## Limits

- A checksum shows the files have not changed. It does not identify who wrote
  them.
- sipnab states no identity it did not establish: sipnab validates no party,
  and the container carries no signature. The
  [vCon guide](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container) lists
  what sipnab leaves out of a container.
- On 0.5.211, when the command includes `--run-provenance-file`, the record and the
  containers carry the system host name as the node, even when `--node-name`
  sets a different one.

## Terms used here

- **SIP**: the signaling protocol that sets up, changes and ends a phone call.
- **Dialog**: one SIP call from its first request to its end.
- **Call-ID**: the identifier SIP gives every message of one call.
- **RTP**: the protocol that carries a call's audio.
- **Capture (pcap)**: a file of network packets recorded from a network
  interface.
- **vCon**: a standard JSON format for a record of one conversation, defined
  by the IETF draft draft-ietf-vcon-vcon-core.
- **Container**: one vCon file.
- **Schema**: the machine-readable rules a vCon file must follow.
- **vCon store (conserver)**: a server that receives and keeps vCon files.
- **Checksum (SHA-256 digest)**: a fixed-length value computed from a file's
  bytes; any change to the file changes it.
- **Signature**: a value that proves who produced a file; sipnab does not
  produce one.
- **Standard output**: the stream a command's results go to, which `>`
  redirects to a file.
- **MCP**: Model Context Protocol, the interface an AI agent or another
  program uses to call sipnab's tools.
- **REST**: sipnab's HTTP API.
- **Provenance record**: the line describing which command produced a result.

## Related guides

- [The spool contract, for a bridge that consumes it](@/docs/vcon.md#the-spool-contract-for-a-bridge-that-consumes-it): the write order and `--vcon-digest`.
- [The container cannot say "this is an incomplete record", so sipnab says it twice](@/docs/vcon.md#the-container-cannot-say-this-is-an-incomplete-record-so-sipnab-says-it-twice): every `capture_completeness` field.
- [Someone handed you a sipnab vCon — what may you conclude?](@/docs/vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude): what the receiver can conclude.
- [What sipnab refuses to put in a container](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container)
- [`validate_vcon`](@/docs/mcp-tools.md#validate-vcon): the tool's arguments and answers.
- [CLI reference: Output](@/docs/cli.md#output): `--export-vcon-when`, `--export-vcon-dir`, `--vcon-digest`, `--no-cli-print`.
- [CLI reference: Security](@/docs/cli.md#security): `--run-provenance-file`.
