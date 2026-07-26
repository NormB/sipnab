+++
title = "Output Formats"
weight = 9
description = "Machine-readable output: NDJSON, summary reports, dialog/stream JSON, and pcap/pcapng."
+++

sipnab has four output modes: interactive TUI (default), per-message CLI
text (`-N`), structured NDJSON (`--json`), and the [MCP server](@/docs/mcp.md).
This page documents the machine-readable formats.

> **Prerequisites:** `--json` requires non-interactive mode (`-N` /
> `--no-tui`) — sipnab refuses to start otherwise (exception:
> `--call-report` implies non-interactive output). No extra build feature
> is needed: NDJSON output is part of the default build. Full flag
> reference: [CLI](@/docs/cli.md#output).

## NDJSON (`--json`)

`--json` emits one JSON object per SIP message — newline-delimited, so
each line is independently parseable and the stream is pipe-friendly:

```bash
sipnab -N -I capture.pcap --json | jq .
```

Message record (fields with no value are omitted, not null):

```json
{
  "schema_version": 1,
  "timestamp": "2026-06-12T14:03:21.412345+00:00",
  "src": "192.0.2.1",
  "src_port": 5060,
  "dst": "192.0.2.2",
  "dst_port": 5060,
  "transport": "UDP",
  "is_request": true,
  "method": "INVITE",
  "call_id": "abc123@192.0.2.1",
  "from": "1001",
  "to": "1002",
  "cseq": { "number": 1, "method": "INVITE" },
  "ua": "FreePBX-16"
}
```

A response record carries `is_request: false` plus `status_code`,
`reason`, and `response_context` instead of `method`:

```json
{
  "schema_version": 1,
  "timestamp": "2026-06-12T14:03:21.598204+00:00",
  "src": "192.0.2.2",
  "src_port": 5060,
  "dst": "192.0.2.1",
  "dst_port": 5060,
  "transport": "UDP",
  "is_request": false,
  "status_code": 180,
  "reason": "Ringing",
  "call_id": "abc123@192.0.2.1",
  "from": "1001",
  "to": "1002",
  "cseq": { "number": 1, "method": "INVITE" },
  "response_context": "1 INVITE"
}
```

Every message — request or response — carries `cseq` (`number` +
`method`) when a parseable CSeq header is present. `response_context`
(`"<number> <method>"`, responses only) is a deprecated alias of `cseq`
retained for backward compatibility under `schema_version` 1 — prefer
`cseq`. Malformed messages additionally carry a `malformed` array of
diagnostic strings; well-formed messages omit it.

`schema_version` increments on breaking field changes — pin your
consumers to it.

### jq recipes

```bash
# Only INVITEs
sipnab -N -I capture.pcap --json | jq 'select(.method == "INVITE")'

# Calls from a specific user
sipnab -N -I capture.pcap --json | jq 'select(.from == "1001")'

# Count messages per method
sipnab -N -I capture.pcap --json \
  | jq -s 'group_by(.method) | map({method: .[0].method, n: length})'

# Failed responses (4xx/5xx/6xx) with their reason
sipnab -N -I capture.pcap --json \
  | jq 'select(.status_code != null and .status_code >= 400)
        | {ts: .timestamp, code: .status_code, reason, call_id}'

# Distinct Call-IDs seen (feed into --call-report)
sipnab -N -I capture.pcap --json | jq -r '.call_id' | sort -u

# Response-code histogram (how many of each status code)
sipnab -N -I capture.pcap --json \
  | jq -r 'select(.is_request == false) | .status_code' \
  | sort | uniq -c | sort -rn
```

## Summary-only output

`--json` prints a line per message. For end-of-run summaries instead,
combine the report flags with
[`--no-cli-print`](@/docs/cli.md#output) (which suppresses the
per-message stream but not the report):

```bash
# Aggregate report only
sipnab -N -I capture.pcap --report --no-cli-print

# Single-call deep dive only
sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1' --no-cli-print
```

## Dialog / stream JSON

The richer aggregated dialog object — `state`, `timing` (PDD / setup /
ring / teardown milliseconds, retransmit counts), `sdp_timeline`,
`streams` with jitter/loss, and the `diagnosis` flags + hints — is one
shape produced by a single serializer. It is documented once, with a
full worked example, under
[`GET /v1/dialogs/{call_id}` in the REST API reference](@/docs/api.md#get-v1-dialogs-1).

The same document is what you get from:

- the REST `GET /v1/dialogs/{call_id}` and
  `GET /v1/dialogs/{call_id}/report` endpoints,
- MCP tool responses (`get_dialog_report` with `format: "json"` — see
  the [MCP server](@/docs/mcp.md) reference), and
- the `SIPNAB_JSON` environment variable passed to
  [`--on-dialog-exec`](@/docs/cli.md#event-execution) hooks (which fill
  `streams: []` and a default `diagnosis`). The `--on-quality-exec` hook is
  separate: it passes the stream object as `SIPNAB_STREAM_JSON`, not
  `SIPNAB_JSON`.

## pcap / pcapng

`-O <file>` writes captured packets; `--pcapng` selects PCAP-NG. With TLS
decryption, `--pcap-export-mode` controls whether decryption secrets
(DSBs) are embedded for Wireshark. Rotation: `--split filesize:N` /
`--split duration:N`, or SIGUSR1 on demand.
